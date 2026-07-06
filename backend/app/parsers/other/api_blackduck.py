import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ApiBlackDuckParser(BaseParser):
    name = "api_blackduck"
    display_name = "Black Duck API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Synopsys Black Duck Hub API report (SCA)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and data:
                first = data[0]
                return (
                    isinstance(first, dict)
                    and "vulnerabilityWithRemediation" in first
                    and "componentName" in first
                )
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for entry in data:
                vuln_info = entry.get("vulnerabilityWithRemediation", {})
                vuln_id = vuln_info.get("vulnerabilityName", "Unknown")
                component_name = entry.get("componentName", "")
                component_version = entry.get("componentVersionName", "")
                title = f"{vuln_id} in {component_name}:{component_version}"

                severity = vuln_info.get("severity", "info").title()
                description = vuln_info.get("description", "")

                cwe_id = None
                cwe_raw = vuln_info.get("cweId", "")
                if cwe_raw:
                    parts = cwe_raw.split("-")
                    if len(parts) == 2 and parts[1].isdigit():
                        cwe_id = int(parts[1])

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool=self.name,
                    description=description,
                    asset=f"{component_name}:{component_version}" if component_name else "unknown",
                    cwe_id=cwe_id,
                    cve_id=vuln_id if vuln_id.upper().startswith("CVE-") else None,
                    raw_data=entry,
                ))
        except Exception:
            pass
        return findings
