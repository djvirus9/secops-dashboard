"""Bounded, read-only GitHub Cloud alert retrieval; no partial result escapes."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import os
import re
import time
from urllib.parse import parse_qsl, urlsplit
import zlib

import httpx

API_ORIGIN = "https://api.github.com"
MAX_ALERTS = 5000
MAX_PAGES = 100
MAX_BYTES = 16 * 1024 * 1024
DEADLINE_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 10
SOURCE_PATHS = {"code_scanning": "code-scanning/alerts", "dependabot": "dependabot/alerts"}


@dataclass(frozen=True)
class RemoteAlert:
    source: str
    number: int
    state: str
    title: str
    severity: str
    description: str = ""
    recommendation: str = ""
    component: str | None = None
    component_version: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_id: str | None = None
    cwe_id: int | None = None
    cvss_score: float | None = None


class GitHubFetchError(Exception):
    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


def validate_repository(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}", value,
    ) or value.split("/")[1] in {".", ".."}:
        raise GitHubFetchError("Invalid GitHub repository; use owner/repo")
    return value.lower()


def _malformed():
    raise GitHubFetchError("GitHub returned malformed alert data; no findings were changed")


def _mapping(value):
    if not isinstance(value, dict):
        _malformed()
    return value


def _text(value, maximum=100_000, *, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()) or "\x00" in value:
        _malformed()
    try:
        if len(value.encode("utf-8")) > maximum:
            _malformed()
    except UnicodeError:
        _malformed()
    return value


def _integer(value, *, optional=False):
    if optional and value is None:
        return None
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        _malformed()
    return value


def _severity(value):
    if not isinstance(value, str) or value not in {"critical", "high", "medium", "low", "info"}:
        _malformed()
    return value


def _code_alert(row):
    rule = _mapping(row.get("rule"))
    instance = _mapping(row.get("most_recent_instance"))
    # GitHub documents most_recent_instance as the default-branch instance when
    # no ref is supplied. Top-level state can be null or describe another state.
    state = instance.get("state")
    if not isinstance(state, str) or state not in {"open", "fixed", "dismissed"}:
        _malformed()
    title = _text(rule.get("description") or rule.get("name") or rule.get("id"), 2000, required=True)
    if len(title) > 500:
        _malformed()
    security_severity = rule.get("security_severity_level")
    ordinary_severity = rule.get("severity")
    if security_severity is None and not isinstance(ordinary_severity, str):
        _malformed()
    severity = _severity(security_severity) if security_severity is not None else {
        "error": "high", "warning": "medium", "note": "low", "none": "info",
    }.get(ordinary_severity)
    if severity is None:
        _malformed()
    location = _mapping(instance.get("location", {}))
    tags = rule.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 1000:
        _malformed()
    cwe = None
    for tag in tags:
        tag = _text(tag, 4096, required=True)
        match = re.search(r"(?:^|/)cwe-([0-9]+)$", tag, re.IGNORECASE)
        if match and cwe is None:
            cwe = _integer(int(match.group(1)))
    return RemoteAlert(
        source="code_scanning", number=_integer(row.get("number")), state=state,
        title=title, severity=severity,
        description=_text(rule.get("full_description") or rule.get("description")) or "",
        recommendation=_text(rule.get("help")) or "Review the affected code and apply the rule's recommended fix.",
        file_path=_text(location.get("path"), 4096),
        line_number=_integer(location.get("start_line"), optional=True), cwe_id=cwe,
    )


def _dependabot_alert(row):
    state = row.get("state")
    if not isinstance(state, str) or state not in {"open", "fixed", "dismissed", "auto_dismissed"}:
        _malformed()
    dependency = _mapping(row.get("dependency"))
    package = _mapping(dependency.get("package"))
    advisory = _mapping(row.get("security_advisory"))
    vulnerability = _mapping(row.get("security_vulnerability"))
    title = _text(advisory.get("summary"), 2000, required=True)
    if len(title) > 500:
        _malformed()
    patched = vulnerability.get("first_patched_version")
    patched_version = _text(_mapping(patched).get("identifier"), 1000, required=True) if patched is not None else None
    cvss = advisory.get("cvss")
    score = _mapping(cvss).get("score") if cvss is not None else None
    if score is not None and (type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 10):
        _malformed()
    cwes = advisory.get("cwes", [])
    if not isinstance(cwes, list) or len(cwes) > 1000:
        _malformed()
    cwe = None
    for value in cwes:
        cwe_text = _text(_mapping(value).get("cwe_id"), 100, required=True)
        match = re.fullmatch(r"CWE-([0-9]+)", cwe_text)
        if not match:
            _malformed()
        if cwe is None:
            cwe = _integer(int(match.group(1)))
    cve = _text(advisory.get("cve_id"), 256)
    if cve is not None and not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
        _malformed()
    return RemoteAlert(
        source="dependabot", number=_integer(row.get("number")), state=state,
        title=title, severity=_severity(advisory.get("severity")),
        description=title,
        recommendation=(f"Upgrade to {patched_version} or a later unaffected version." if patched_version
                        else "Review the advisory and upgrade to an unaffected version when available."),
        component=_text(package.get("name"), 2000, required=True),
        component_version=_text(vulnerability.get("vulnerable_version_range"), 1000),
        file_path=_text(dependency.get("manifest_path"), 4096),
        cve_id=cve, cwe_id=cwe,
        cvss_score=float(score) if score is not None else None,
    )


def _redact_credentials(alert: RemoteAlert, credential: str) -> RemoteAlert:
    # The server credential may be echoed in malicious rule/advisory text. It
    # never belongs in findings, their hashes, notification payloads, or errors.
    limits = {"title": 2000, "description": 100_000, "recommendation": 100_000,
              "component": 2000, "component_version": 1000, "file_path": 4096, "cve_id": 256}
    changes = {}
    for name, limit in limits.items():
        value = getattr(alert, name)
        if value is not None:
            changes[name] = _text(value.replace(credential, "[REDACTED]"), limit)
    if len(changes["title"]) > 500:
        _malformed()
    return replace(alert, **changes)


def _next_params(header: str, path: str, source: str) -> dict[str, str] | None:
    if not header:
        return None
    if len(header) > 16_384:
        raise GitHubFetchError("GitHub returned invalid pagination; no findings were changed")
    links = header.split(",")
    next_url = None
    for link in links:
        match = re.fullmatch(r'\s*<([^<>]+)>\s*;\s*rel="([a-z ]+)"\s*', link)
        if not match:
            raise GitHubFetchError("GitHub returned invalid pagination; no findings were changed")
        if "next" in match.group(2).split():
            if next_url is not None:
                raise GitHubFetchError("GitHub returned duplicate pagination links; no findings were changed")
            next_url = match.group(1)
    if next_url is None:
        return None
    try:
        if any(ord(char) < 33 or ord(char) > 126 for char in next_url) or re.search(r"%(?![0-9A-Fa-f]{2})", next_url):
            raise ValueError()
        url = urlsplit(next_url)
        # Never request the provided URL. Only pagination values survive into
        # the next request to our fixed host and exact repository path.
        if url.scheme != "https" or url.netloc != "api.github.com" or url.path != path or url.fragment:
            raise ValueError()
        pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
        params = dict(pairs)
        allowed = {"per_page", "after", "before"} | ({"page"} if source == "code_scanning" else set())
        if len(params) != len(pairs) or not set(params) <= allowed:
            raise ValueError()
        if params.get("per_page", "100") != "100":
            raise ValueError()
        positions = set(params) - {"per_page"}
        if len(positions) != 1:
            raise ValueError()
        key = next(iter(positions))
        value = params[key]
        if not value or len(value) > 2000 or any(ord(char) < 33 or ord(char) > 126 for char in value):
            raise ValueError()
        if key == "page" and (not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= MAX_PAGES):
            raise ValueError()
        return {"per_page": "100", key: value}
    except (ValueError, UnicodeError):
        raise GitHubFetchError("GitHub returned unsafe pagination; no findings were changed") from None


def _retry_after(headers: httpx.Headers) -> int | None:
    value = headers.get("retry-after", "")
    if value:
        try:
            seconds = int(value) if value.isdecimal() else math.ceil(
                (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
            return min(86400, max(1, seconds))
        except (ValueError, TypeError, OverflowError):
            pass
    if headers.get("x-ratelimit-remaining") == "0":
        try:
            return min(86400, max(1, math.ceil(float(headers.get("x-ratelimit-reset", "")) - time.time())))
        except (ValueError, OverflowError):
            pass
    return None


def _check_status(response):
    if response.status_code == 200:
        return
    if response.status_code in {403, 429}:
        retry = _retry_after(response.headers)
        if response.status_code == 429 or retry is not None:
            raise GitHubFetchError("GitHub rate limit reached; synchronization will retry", retry or 60)
    messages = {
        401: "GitHub credential was rejected; check GITHUB_SYNC_TOKEN",
        403: "GitHub denied access; check alert permissions and repository security settings",
        404: "GitHub repository or alerts unavailable; check repository access and enabled sources",
    }
    raise GitHubFetchError(messages.get(response.status_code, "GitHub request failed; no findings were changed"))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _malformed()
        result[key] = value
    return result


async def _read_page(response, remaining):
    # Decode ourselves with an output cap. A compressed body must not allocate
    # an unbounded decompressed buffer inside the HTTP client's decoder.
    encoding = response.headers.get("content-encoding", "identity").lower()
    if encoding not in {"identity", "gzip", "deflate"}:
        raise GitHubFetchError("GitHub returned unsupported response encoding")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding != "identity" else None
    body = bytearray()
    raw_size = 0
    async for chunk in response.aiter_raw(chunk_size=16_384):
        raw_size += len(chunk)
        if raw_size > MAX_BYTES + 1024 * 1024:
            raise GitHubFetchError("GitHub response size limit exceeded; no findings were changed")
        decoded = decoder.decompress(chunk, remaining - len(body) + 1) if decoder else chunk
        body.extend(decoded)
        if len(body) > remaining or (decoder and (decoder.unconsumed_tail or decoder.unused_data)):
            raise GitHubFetchError("GitHub response size limit exceeded or invalid encoding; no findings were changed")
    if decoder and not decoder.eof:
        raise GitHubFetchError("GitHub returned incomplete compressed data; no findings were changed")
    try:
        page = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: _malformed())
    except (UnicodeError, ValueError, RecursionError):
        _malformed()
    if not isinstance(page, list) or len(page) > 100:
        _malformed()
    return page, len(body)


async def _fetch(repository, sources, credential):
    results, seen = [], set()
    pages = byte_count = 0
    deadline = time.monotonic() + DEADLINE_SECONDS
    async with asyncio.timeout(DEADLINE_SECONDS):
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False,
            headers={"Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                     "Authorization": f"Bearer {credential}", "X-GitHub-Api-Version": "2026-03-10",
                     "User-Agent": "SecOps-Dashboard"},
        ) as client:
            for source in sources:
                path = f"/repos/{repository}/{SOURCE_PATHS[source]}"
                params, visited = {"per_page": "100"}, set()
                while params is not None:
                    position = tuple(sorted(params.items()))
                    if position in visited:
                        raise GitHubFetchError("GitHub pagination loop detected; no findings were changed")
                    visited.add(position)
                    pages += 1
                    if pages > MAX_PAGES:
                        raise GitHubFetchError("GitHub page limit exceeded; no findings were changed")
                    async with client.stream("GET", API_ORIGIN + path, params=params) as response:
                        _check_status(response)
                        page, size = await _read_page(response, MAX_BYTES - byte_count)
                        byte_count += size
                        params = _next_params(response.headers.get("link", ""), path, source)
                        if params and any(credential in value for value in params.values()):
                            raise GitHubFetchError("GitHub returned invalid pagination; no findings were changed")
                    if not page and params is not None:
                        raise GitHubFetchError("GitHub returned incomplete pagination; no findings were changed")
                    for row in page:
                        alert = (_code_alert if source == "code_scanning" else _dependabot_alert)(_mapping(row))
                        identity = (alert.source, alert.number)
                        if identity in seen:
                            raise GitHubFetchError("GitHub returned duplicate alerts; retry the complete sync")
                        seen.add(identity)
                        results.append(_redact_credentials(alert, credential))
                        if len(results) > MAX_ALERTS:
                            raise GitHubFetchError("GitHub alert limit exceeded; no findings were changed")
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
    return results


def fetch_alerts(repository: str, sources: list[str]) -> list[RemoteAlert]:
    """Synchronous worker interface; the async transport enforces a total deadline."""
    repository = validate_repository(repository)
    if not isinstance(sources, (list, tuple)) or not 1 <= len(sources) <= 2 or any(
        not isinstance(source, str) or source not in SOURCE_PATHS for source in sources
    ) or len(set(sources)) != len(sources):
        raise GitHubFetchError("Select valid, distinct GitHub alert sources")
    credential = os.environ.get("GITHUB_SYNC_TOKEN", "")
    if not 32 <= len(credential) <= 512 or not re.fullmatch(r"[!-~]+", credential):
        raise GitHubFetchError("Configure a valid GITHUB_SYNC_TOKEN on the server")
    try:
        return asyncio.run(_fetch(repository, sources, credential))
    except (TimeoutError, httpx.TimeoutException):
        raise GitHubFetchError("GitHub request timed out; no findings were changed") from None
    except (httpx.HTTPError, zlib.error):
        raise GitHubFetchError("GitHub transport failed; no findings were changed") from None
