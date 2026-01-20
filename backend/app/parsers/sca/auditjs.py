import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class AuditJSParser(BaseParser):
    name = "auditjs"
    display_name = "AuditJS"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "AuditJS for auditing JavaScript packages via npm registry"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "coordinates" in data[0] or "vulnerabilities" in data[0]
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for item in data:
                coords = item.get("coordinates", "unknown")
                for vuln in item.get("vulnerabilities", []):
                    findings.append(ParsedFinding(
                        title=vuln.get("title", vuln.get("id", "AuditJS Vulnerability")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", vuln.get("cvssScore", "medium"))),
                        tool=self.name,
                        asset=coords,
                        cve=vuln.get("cve"),
                        cvss_score=vuln.get("cvssScore"),
                        raw_data={"coordinates": coords, **vuln}
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev) -> str:
        if isinstance(sev, (int, float)):
            if sev >= 9.0: return "critical"
            if sev >= 7.0: return "high"
            if sev >= 4.0: return "medium"
            return "low"
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
