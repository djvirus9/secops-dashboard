"""Small Jira Cloud client: fixed tenant, no redirects, bounded JSON, safe errors.

API contracts: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
Rate limits: https://developer.atlassian.com/cloud/jira/platform/rate-limiting/
"""
from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

MAX_BYTES = 128 * 1024
KEY_PATTERN = r"[A-Z][A-Z0-9_]{0,49}-[1-9][0-9]{0,19}"
ACCOUNT_PATTERN = r"[A-Za-z0-9:_-]{1,128}"


class JiraError(Exception):
    def __init__(self, message: str, *, retry_after: int | None = None, uncertain: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.uncertain = uncertain


@dataclass(frozen=True)
class Settings:
    base_url: str
    email: str
    token: str


def enabled() -> bool:
    return os.environ.get("JIRA_SYNC_ENABLED", "false").strip().lower() == "true"


def settings() -> Settings:
    # Standard Jira Cloud only. Do not permit credentials, ports, paths, URL
    # escapes, arbitrary hosts, or tenant-changing links from remote payloads.
    value = os.environ.get("JIRA_BASE_URL", "")
    if not re.fullmatch(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net/?", value):
        raise JiraError("Configure a standard HTTPS Jira Cloud tenant URL on the server")
    base = value.rstrip("/")
    email, token = os.environ.get("JIRA_EMAIL", ""), os.environ.get("JIRA_API_TOKEN", "")
    if not email or not token:
        raise JiraError("Configure Jira credentials on the server")
    return Settings(base, email, token)


def configured() -> bool:
    try:
        settings()
        return True
    except JiraError:
        return False


def interval_minutes() -> int:
    try:
        return max(15, min(1440, int(os.environ.get("JIRA_SYNC_INTERVAL_MINUTES", "30"))))
    except ValueError:
        return 30


def valid_key(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(KEY_PATTERN, value) is not None


def _text(value: object, maximum: int, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise JiraError("Jira returned an invalid progress response")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise JiraError("Jira returned an invalid progress response")
    if identifier and not re.fullmatch(ACCOUNT_PATTERN, value):
        raise JiraError("Jira returned an invalid progress response")
    return value


def _retry_after(value: str | None) -> int:
    try:
        seconds = int(value or "60")
    except ValueError:
        try:
            deadline = parsedate_to_datetime(value or "")
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            seconds = int((deadline - datetime.now(UTC)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            seconds = 60
    return max(1, min(86400, seconds))


class JiraClient:
    def __init__(self, config: Settings | None = None):
        self.config = config or settings()

    def _request(self, method: str, key: str, suffix: str = "", **kwargs):
        if not valid_key(key) or suffix not in {"", "/transitions", "/assignee"}:
            raise JiraError("Invalid Jira issue reference")
        write = method != "GET"
        deadline = time.monotonic() + 20
        try:
            with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
                with client.stream(method, self.config.base_url + "/rest/api/3/issue/" + key + suffix,
                                   auth=(self.config.email, self.config.token),
                                   headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                                   **kwargs) as response:
                    if response.status_code == 429:
                        raise JiraError("Jira rate limit reached; retry is scheduled",
                                        retry_after=_retry_after(response.headers.get("Retry-After")))
                    if response.status_code not in ({200} if not write else {200, 204}):
                        raise JiraError(f"Jira returned HTTP {response.status_code}; check integration permissions",
                                        retry_after=60 if response.status_code >= 500 and not write else None,
                                        uncertain=write and response.status_code >= 500)
                    if write:
                        return None
                    # Reject compression rather than risking unbounded decode.
                    if response.headers.get("Content-Encoding", "identity") not in {"", "identity"}:
                        raise JiraError("Jira returned an unsupported encoded response")
                    body = bytearray()
                    for chunk in response.iter_raw(chunk_size=8192):
                        if len(body) + len(chunk) > MAX_BYTES or time.monotonic() > deadline:
                            raise JiraError("Jira progress response exceeded safe limits")
                        body.extend(chunk)
                    value = json.loads(body)
                    if not isinstance(value, dict):
                        raise JiraError("Jira returned an invalid progress response")
                    return value
        except (httpx.HTTPError, ValueError, UnicodeError) as exc:
            raise JiraError("Jira request failed; check connectivity and integration settings",
                            retry_after=None if write else 60, uncertain=write) from exc

    def issue(self, key: str) -> dict:
        data = self._request("GET", key, params={"fields": "status,assignee,updated"})
        try:
            if data.get("key") != key:
                raise JiraError("Jira returned a different issue; review its link")
            fields = data["fields"]
            status = fields["status"]
            category = status["statusCategory"]["key"]
            if category not in {"new", "indeterminate", "done"}:
                raise JiraError("Jira returned an unsupported status category")
            modified = _text(fields["updated"], 64)
            parsed = datetime.fromisoformat(modified.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise JiraError("Jira returned an invalid update timestamp")
            owner = fields.get("assignee")
            return {"status_id": _text(status["id"], 128, identifier=True),
                    "status": _text(status["name"], 200), "category": category,
                    "assignee_id": _text(owner["accountId"], 128, identifier=True) if owner else None,
                    "assignee": _text(owner.get("displayName", owner["accountId"]), 200) if owner else None,
                    "updated_at": modified}
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise JiraError("Jira returned an invalid progress response") from exc

    def transition(self, key: str, category: str) -> None:
        data = self._request("GET", key, "/transitions")
        try:
            transitions = data["transitions"]
            if not isinstance(transitions, list) or len(transitions) > 100:
                raise JiraError("Jira returned an invalid transitions response")
            candidates = [item for item in transitions if item["to"]["statusCategory"]["key"] == category]
            if len(candidates) != 1:
                raise JiraError("No unique matching Jira transition; choose the transition in Jira")
            transition_id = _text(candidates[0]["id"], 128, identifier=True)
        except (KeyError, TypeError) as exc:
            raise JiraError("Jira returned an invalid transitions response") from exc
        self._request("POST", key, "/transitions", json={"transition": {"id": transition_id}})

    def assign(self, key: str, account_id: str | None) -> None:
        if account_id is not None:
            _text(account_id, 128, identifier=True)
        self._request("PUT", key, "/assignee", json={"accountId": account_id})
