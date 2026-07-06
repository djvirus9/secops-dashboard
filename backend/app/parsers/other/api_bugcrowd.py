import json
import textwrap
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _convert_severity(bugcrowd_severity: int) -> str:
    mapping = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
    return mapping.get(int(bugcrowd_severity), "info")


@ParserRegistry.register
class ApiBugcrowdParser(BaseParser):
    name = "api_bugcrowd"
    display_name = "Bugcrowd API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Bugcrowd API submission export"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and data:
                first = data[0]
                return (
                    isinstance(first, dict)
                    and "attributes" in first
                    and "state" in first.get("attributes", {})
                    and "severity" in first.get("attributes", {})
                )
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for entry in data:
                attrs = entry.get("attributes", {})
                title = attrs.get("title", "Bugcrowd Submission")
                title = textwrap.shorten(title, width=511, placeholder="...")
                severity_num = attrs.get("severity", 5)
                sev_str = _convert_severity(severity_num)
                state = attrs.get("state", "new")
                description = attrs.get("description", "")
                bug_url = (attrs.get("bug_url") or "").strip()
                if bug_url:
                    description += f"\n\n**Bug URL**: {bug_url}"

                links = entry.get("links", {})
                link_self = links.get("self", "")
                if link_self:
                    description += f"\n\n**Bugcrowd Link**: {link_self}"

                mitigation = attrs.get("remediation_advice", "")
                asset = bug_url or "unknown"

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev_str),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    recommendation=mitigation,
                    raw_data=entry,
                ))
        except Exception:
            pass
        return findings
