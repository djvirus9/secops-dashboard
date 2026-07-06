import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CoverityApiParser(BaseParser):
    name = "coverity_api"
    display_name = "Coverity API"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Synopsys Coverity API view data (/api/viewContents/issues endpoint)"

    IMPACT_MAP = {
        "Audit": "info",
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "viewContentsV1" in data and "rows" in data.get("viewContentsV1", {})
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        rows = data.get("viewContentsV1", {}).get("rows", [])
        for issue in rows:
            kind = issue.get("displayIssueKind")
            checker = issue.get("checker", "")
            # Only security findings and Quality RESOURCE_LEAK
            if not (kind == "Security" or (kind == "Quality" and checker == "RESOURCE_LEAK")):
                continue

            title = issue.get("displayType", "Unknown")
            impact = issue.get("displayImpact")
            severity_str = self.IMPACT_MAP.get(impact, "info") if impact else "info"

            description = "\n".join([
                f"**CID:** `{issue.get('cid', '')}`",
                f"**Type:** `{issue.get('displayType', '')}`",
                f"**Status:** `{issue.get('status', '')}`",
                f"**Classification:** `{issue.get('classification', '')}`",
            ])

            file_path = issue.get("displayFile")
            cwe_raw = issue.get("cwe")
            cwe_id = None
            if isinstance(cwe_raw, int) and cwe_raw > 0:
                cwe_id = cwe_raw

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="coverity_api",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=None,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data=issue,
            ))
        return findings
