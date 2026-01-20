import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class TwistlockParser(BaseParser):
    name = "twistlock"
    display_name = "Twistlock / Prisma Cloud"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Palo Alto Prisma Cloud (formerly Twistlock) container security"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and ("vulnerabilities" in str(data) or "complianceIssues" in str(data)) or "twistlock" in str(data).lower() or "prisma" in str(data).lower()
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("results", [data])
            for result in results:
                image = result.get("id", result.get("imageName", "unknown"))
                for vuln in result.get("vulnerabilities", []):
                    findings.append(ParsedFinding(
                        title=vuln.get("cve", vuln.get("id", "Twistlock Vulnerability")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", "medium")),
                        tool=self.name,
                        asset=f"{image}:{vuln.get('packageName', 'unknown')}@{vuln.get('packageVersion', '')}",
                        cve=vuln.get("cve"),
                        cvss_score=vuln.get("cvss"),
                        raw_data=vuln
                    ))
                for issue in result.get("complianceIssues", []):
                    findings.append(ParsedFinding(
                        title=issue.get("title", issue.get("id", "Twistlock Compliance Issue")),
                        description=issue.get("description", ""),
                        severity=self._map_severity(issue.get("severity", "medium")),
                        tool=self.name,
                        asset=image,
                        raw_data=issue
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "important": "high"}
        return mapping.get(str(sev).lower(), "medium")
