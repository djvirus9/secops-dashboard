import json
import re
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

PTART_SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "info",
}


def _parse_ptart_severity(severity_val) -> str:
    if severity_val is None:
        return "info"
    try:
        return PTART_SEVERITY_MAP.get(int(severity_val), "info")
    except (ValueError, TypeError):
        return str(severity_val).lower()


def _parse_cwe_from_hit(hit: dict) -> Optional[int]:
    """Extract CWE ID from hit labels or cvss_vector."""
    for label in hit.get("labels", []):
        match = re.search(r"CWE-(\d+)", str(label), re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _extract_urls_from_hit(hit: dict) -> List[str]:
    """Extract unique URLs from hit's affected_urls."""
    urls = []
    for item in hit.get("affected_urls", []):
        url = item.get("url") or item if isinstance(item, str) else None
        if url:
            urls.append(url)
    return urls


@ParserRegistry.register
class PTARTParser(BaseParser):
    name = "ptart"
    display_name = "PTART"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "PTART pentest management tool report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and (
                "assessments" in data or "retest_campaigns" in data
            )
        except Exception:
            return False

    def _parse_hit(self, hit: dict, component_name: str = "Unknown") -> ParsedFinding:
        title = hit.get("title", "Unknown Finding")
        severity_val = hit.get("severity")
        severity_str = _parse_ptart_severity(severity_val)

        description = hit.get("body", "")
        mitigation = hit.get("remediation", "")

        cwe_id = _parse_cwe_from_hit(hit)

        cvss_score = None
        cvss_vector = hit.get("cvss_vector", "")
        if cvss_vector:
            # Try to extract base score from vector string
            score_match = re.search(r"/S:(\d+\.\d+)", cvss_vector)
            if not score_match:
                score_match = re.search(r"(\d+\.\d+)$", cvss_vector)
            if score_match:
                try:
                    cvss_score = float(score_match.group(1))
                except ValueError:
                    pass

        urls = _extract_urls_from_hit(hit)
        asset = urls[0] if urls else component_name

        # References
        references = []
        for ref in hit.get("references", []):
            if isinstance(ref, str):
                references.append(ref)
            elif isinstance(ref, dict):
                ref_url = ref.get("url") or ref.get("reference") or str(ref)
                references.append(ref_url)

        tags = [str(t) for t in hit.get("labels", [])]

        return ParsedFinding(
            title=title,
            severity=Severity.normalize(severity_str),
            tool="ptart",
            description=description,
            asset=asset,
            cwe_id=cwe_id,
            cve_id=hit.get("id") if str(hit.get("id", "")).upper().startswith("CVE") else None,
            cvss_score=cvss_score,
            recommendation=mitigation,
            references=references,
            tags=tags,
            raw_data=hit,
        )

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        # Parse assessments
        for assessment in data.get("assessments", []):
            component_name = assessment.get("title", "Unknown Component")
            for hit in assessment.get("hits", []):
                findings.append(self._parse_hit(hit, component_name))

        # Parse retest campaigns
        for campaign in data.get("retest_campaigns", []):
            for retest in campaign.get("retests", []):
                component_name = retest.get("title", campaign.get("name", "Unknown"))
                for hit in retest.get("hits", []):
                    findings.append(self._parse_hit(hit, component_name))

        return findings
