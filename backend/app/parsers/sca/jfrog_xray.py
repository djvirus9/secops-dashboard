import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class JFrogXrayParser(BaseParser):
    name = "jfrog_xray"
    display_name = "JFrog Xray"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "JFrog Xray universal software composition analysis"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "security_violations" in data or "vulnerabilities" in data and "xray" in str(data).lower() or "violations" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            violations = data.get("security_violations", data.get("violations", data.get("vulnerabilities", [])))
            for violation in violations:
                components = violation.get("components", [{}])
                for comp in components:
                    findings.append(ParsedFinding(
                        title=violation.get("summary", violation.get("cve", violation.get("issue_id", "JFrog Xray Finding"))),
                        description=violation.get("description", ""),
                        severity=self._map_severity(violation.get("severity", "medium")),
                        tool=self.name,
                        asset=comp.get("component_id", comp.get("id", violation.get("impacted_artifact", "unknown"))),
                        cve=violation.get("cve"),
                        cvss_score=violation.get("cvss_v3_score", violation.get("cvss_v2_score")),
                        raw_data={**violation, "component": comp}
                    ))
                if not components:
                    findings.append(ParsedFinding(
                        title=violation.get("summary", violation.get("cve", "JFrog Xray Finding")),
                        description=violation.get("description", ""),
                        severity=self._map_severity(violation.get("severity", "medium")),
                        tool=self.name,
                        asset=violation.get("impacted_artifact", "unknown"),
                        cve=violation.get("cve"),
                        cvss_score=violation.get("cvss_v3_score"),
                        raw_data=violation
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "unknown": "info"}
        return mapping.get(str(sev).lower(), "medium")
