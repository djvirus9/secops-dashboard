"""Bounded clients for fixed, public vulnerability-intelligence endpoints."""
from __future__ import annotations

from datetime import date
import json
import re

import httpx


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_KEV_BYTES = 8 * 1024 * 1024
MAX_EPSS_BYTES = 2 * 1024 * 1024
MAX_EPSS_BATCH = 100
MAX_EPSS_CVES = 10_000
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)


class IntelligenceFetchError(Exception):
    pass


def normalize_cve(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if len(candidate) <= 20 and CVE_PATTERN.fullmatch(candidate) else None


def _json_response(url: str, *, params: dict | None = None, limit: int) -> dict:
    try:
        with httpx.Client(
            timeout=httpx.Timeout(20, connect=5),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "User-Agent": "secops-dashboard-intelligence/0.4"},
        ) as client:
            with client.stream("GET", url, params=params) as response:
                if response.is_redirect:
                    raise IntelligenceFetchError("The intelligence source returned an unexpected redirect")
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    raise IntelligenceFetchError("The intelligence source returned an unexpected content type")
                length = response.headers.get("content-length")
                if length and int(length) > limit:
                    raise IntelligenceFetchError("The intelligence response exceeded its size limit")
                # Bound decoded bytes while reading; checking response.content
                # afterward would still permit a compressed response to exhaust
                # memory before the limit is enforced.
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > limit:
                        raise IntelligenceFetchError("The intelligence response exceeded its size limit")
                    body.extend(chunk)
                parsed = json.loads(body)
    except IntelligenceFetchError:
        raise
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise IntelligenceFetchError("The intelligence source could not be validated") from exc
    if not isinstance(parsed, dict):
        raise IntelligenceFetchError("The intelligence source returned an invalid document")
    return parsed


def fetch_kev() -> list[dict]:
    document = _json_response(CISA_KEV_URL, limit=MAX_KEV_BYTES)
    raw_items = document.get("vulnerabilities")
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 100_000:
        raise IntelligenceFetchError("The CISA KEV catalog has an invalid record collection")
    items = []
    seen = set()
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise IntelligenceFetchError("The CISA KEV catalog contains an invalid record")
        cve_id = normalize_cve(raw.get("cveID"))
        if not cve_id:
            raise IntelligenceFetchError("The CISA KEV catalog contains an invalid CVE identifier")
        if cve_id in seen:
            raise IntelligenceFetchError("The CISA KEV catalog contains a duplicate CVE identifier")
        seen.add(cve_id)
        try:
            date_added = date.fromisoformat(str(raw.get("dateAdded")))
            due_date = date.fromisoformat(str(raw.get("dueDate")))
        except ValueError as exc:
            raise IntelligenceFetchError("The CISA KEV catalog contains an invalid date") from exc
        required_action = raw.get("requiredAction")
        if not isinstance(required_action, str) or not 1 <= len(required_action) <= 4000:
            raise IntelligenceFetchError("The CISA KEV catalog contains an invalid action")
        ransomware = str(raw.get("knownRansomwareCampaignUse", "Unknown")).strip().lower() == "known"
        items.append({
            "cve_id": cve_id,
            "kev_date_added": date_added,
            "kev_due_date": due_date,
            "kev_ransomware": ransomware,
            "kev_required_action": required_action,
        })
    return items


def fetch_epss(cve_ids: list[str]) -> list[dict]:
    normalized = sorted({value for item in cve_ids if (value := normalize_cve(item))})
    if len(normalized) > MAX_EPSS_CVES:
        raise IntelligenceFetchError("The EPSS refresh exceeded its CVE work limit")
    items = []
    for offset in range(0, len(normalized), MAX_EPSS_BATCH):
        batch = normalized[offset:offset + MAX_EPSS_BATCH]
        document = _json_response(
            FIRST_EPSS_URL,
            params={"cve": ",".join(batch)},
            limit=MAX_EPSS_BYTES,
        )
        raw_items = document.get("data")
        if not isinstance(raw_items, list) or len(raw_items) > len(batch):
            raise IntelligenceFetchError("The FIRST EPSS response has an invalid record collection")
        seen = set()
        for raw in raw_items:
            if not isinstance(raw, dict) or not (cve_id := normalize_cve(raw.get("cve"))):
                raise IntelligenceFetchError("The FIRST EPSS response contains an invalid CVE identifier")
            if cve_id not in batch or cve_id in seen:
                raise IntelligenceFetchError("The FIRST EPSS response contains an unexpected CVE identifier")
            seen.add(cve_id)
            try:
                score = float(raw.get("epss"))
                percentile = float(raw.get("percentile"))
            except (TypeError, ValueError) as exc:
                raise IntelligenceFetchError("The FIRST EPSS response contains an invalid score") from exc
            if not 0 <= score <= 1 or not 0 <= percentile <= 1:
                raise IntelligenceFetchError("The FIRST EPSS response contains an out-of-range score")
            items.append({"cve_id": cve_id, "epss_score": score, "epss_percentile": percentile})
    return items
