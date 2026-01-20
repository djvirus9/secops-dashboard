import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class KubeHunterParser(BaseParser):
    name = "kube_hunter"
    display_name = "kube-hunter"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Kubernetes penetration testing tool"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("hunter_statistics" in data or "nodes" in data or "services" in data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for vuln in data.get("vulnerabilities", []):
                findings.append(ParsedFinding(
                    title=vuln.get("vulnerability", vuln.get("location", "kube-hunter Finding")),
                    description=vuln.get("description", vuln.get("evidence", "")),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=self.name,
                    asset=vuln.get("location", vuln.get("category", "kubernetes")),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
