import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class GitLabSASTParser(BaseParser):
    name = "gitlab_sast"
    display_name = "GitLab SAST/DAST"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "GitLab Security Scanning (SAST, DAST, Secret Detection)"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("version" in data or "scan" in data or "remediations" in data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            scan_type = data.get("scan", {}).get("type", "gitlab")
            for vuln in data.get("vulnerabilities", []):
                location = vuln.get("location", {})
                identifiers = vuln.get("identifiers", [])
                cve = None
                cwe = None
                for ident in identifiers:
                    if ident.get("type") == "cve":
                        cve = ident.get("value")
                    if ident.get("type") == "cwe":
                        cwe = ident.get("value")
                findings.append(ParsedFinding(
                    title=vuln.get("name", vuln.get("message", "GitLab Finding")),
                    description=vuln.get("description", ""),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=f"gitlab_{scan_type}",
                    asset=location.get("file", location.get("hostname", "unknown")),
                    cve=cve,
                    cwe=cwe,
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
        return mapping.get(str(sev).lower(), "medium")
