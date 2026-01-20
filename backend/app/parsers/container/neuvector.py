import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class NeuVectorParser(BaseParser):
    name = "neuvector"
    display_name = "NeuVector"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "NeuVector full lifecycle container security"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "report" in data and "vulnerabilities" in data.get("report", {}) or "neuvector" in str(data).lower()
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            report = data.get("report", data)
            vulns = report.get("vulnerabilities", [])
            image = report.get("image_id", report.get("repository", "unknown"))
            for vuln in vulns:
                findings.append(ParsedFinding(
                    title=vuln.get("name", "NeuVector Vulnerability"),
                    description=vuln.get("description", ""),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=self.name,
                    asset=f"{image}:{vuln.get('package_name', 'unknown')}@{vuln.get('package_version', '')}",
                    cve=vuln.get("name") if str(vuln.get("name", "")).startswith("CVE") else None,
                    cvss_score=vuln.get("score"),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
