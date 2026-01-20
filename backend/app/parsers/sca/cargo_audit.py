import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CargoAuditParser(BaseParser):
    name = "cargo_audit"
    display_name = "Cargo Audit"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Rust cargo-audit for auditing Cargo.lock dependencies"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("database" in data or "lockfile" in data) or "warnings" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            vulns = data.get("vulnerabilities", {})
            vuln_list = vulns.get("list", []) if isinstance(vulns, dict) else vulns
            for vuln in vuln_list:
                advisory = vuln.get("advisory", {})
                package = vuln.get("package", {})
                findings.append(ParsedFinding(
                    title=advisory.get("title", advisory.get("id", "Cargo Audit Vulnerability")),
                    description=advisory.get("description", ""),
                    severity=self._map_severity(advisory.get("severity", vuln.get("severity", "medium"))),
                    tool=self.name,
                    asset=f"{package.get('name', 'unknown')}@{package.get('version', '')}",
                    cve=advisory.get("id") if advisory.get("id", "").startswith("CVE") else None,
                    raw_data=vuln
                ))
            for warning in data.get("warnings", {}).get("unmaintained", []):
                advisory = warning.get("advisory", {})
                package = warning.get("package", {})
                findings.append(ParsedFinding(
                    title=f"Unmaintained: {advisory.get('title', package.get('name', 'Unknown'))}",
                    description=advisory.get("description", "This package is unmaintained"),
                    severity="low",
                    tool=self.name,
                    asset=f"{package.get('name', 'unknown')}@{package.get('version', '')}",
                    raw_data=warning
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
