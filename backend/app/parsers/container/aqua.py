import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class AquaParser(BaseParser):
    name = "aqua"
    display_name = "Aqua Security"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Aqua Security container and cloud-native security"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "resources" in data or "image_assurance" in data or "aqua" in str(data).lower() and "vulnerabilities" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            resources = data.get("resources", [data])
            for resource in resources:
                vulns = resource.get("vulnerabilities", resource.get("results", []))
                image = resource.get("resource", {}).get("name", resource.get("image", "unknown"))
                for vuln in vulns:
                    findings.append(ParsedFinding(
                        title=vuln.get("name", vuln.get("vulnerability_id", "Aqua Finding")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("aqua_severity", vuln.get("severity", "medium"))),
                        tool=self.name,
                        asset=image,
                        cve=vuln.get("name") if str(vuln.get("name", "")).startswith("CVE") else None,
                        cvss_score=vuln.get("aqua_score", vuln.get("nvd_score")),
                        raw_data=vuln
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info"}
        return mapping.get(str(sev).lower(), "medium")
