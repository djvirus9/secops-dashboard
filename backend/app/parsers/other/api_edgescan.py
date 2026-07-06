import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

_ES_SEVERITIES = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


@ParserRegistry.register
class ApiEdgescanParser(BaseParser):
    name = "api_edgescan"
    display_name = "Edgescan API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Edgescan continuous vulnerability management API export"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and data:
                first = data[0]
                return (
                    isinstance(first, dict)
                    and "name" in first
                    and "severity" in first
                    and "date_opened" in first
                )
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for vuln in data:
                title = vuln.get("name", "Edgescan Finding")
                sev_int = vuln.get("severity", 1)
                sev_str = _ES_SEVERITIES.get(sev_int, "info")
                description = vuln.get("description", "")
                mitigation = vuln.get("remediation", "")
                location = vuln.get("location", "unknown")
                cves = vuln.get("cves", [])
                cve_id = cves[0] if cves else None
                cwes = vuln.get("cwes", [])
                cwe_id = None
                if cwes:
                    try:
                        cwe_id = int(cwes[0][4:])  # strip "CWE-" prefix
                    except (ValueError, IndexError):
                        pass

                cvss_score = None
                if vuln.get("cvss_version") == 3 and vuln.get("cvss_vector"):
                    # Store vector string as reference; score not directly available
                    pass

                tags = []
                if vuln.get("asset_tags"):
                    tags = [t.strip() for t in vuln["asset_tags"].split(",") if t.strip()]

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev_str),
                    tool=self.name,
                    description=description,
                    asset=location,
                    recommendation=mitigation,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    tags=tags,
                    raw_data=vuln,
                ))
        except Exception:
            pass
        return findings
