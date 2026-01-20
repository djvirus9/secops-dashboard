import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class GovulncheckParser(BaseParser):
    name = "govulncheck"
    display_name = "Govulncheck"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Go vulnerability checker for Go modules"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulns" in data or "Vulns" in data or "entries" in data and "go.mod" in str(data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            vulns = data.get("vulns", data.get("Vulns", data.get("entries", [])))
            for vuln in vulns:
                osv = vuln.get("osv", vuln)
                modules = vuln.get("modules", [{}])
                for mod in modules:
                    pkg_path = mod.get("path", osv.get("id", "unknown"))
                    findings.append(ParsedFinding(
                        title=osv.get("summary", osv.get("id", "Govulncheck Finding")),
                        description=osv.get("details", ""),
                        severity=self._map_severity(osv.get("database_specific", {}).get("severity", "medium")),
                        tool=self.name,
                        asset=pkg_path,
                        cve=self._extract_cve(osv.get("aliases", [])),
                        raw_data={**osv, "module": mod}
                    ))
                if not modules:
                    findings.append(ParsedFinding(
                        title=osv.get("summary", osv.get("id", "Govulncheck Finding")),
                        description=osv.get("details", ""),
                        severity=self._map_severity(osv.get("database_specific", {}).get("severity", "medium")),
                        tool=self.name,
                        asset=osv.get("id", "unknown"),
                        cve=self._extract_cve(osv.get("aliases", [])),
                        raw_data=osv
                    ))
        except:
            pass
        return findings

    def _extract_cve(self, aliases: list) -> str | None:
        for alias in aliases:
            if alias.startswith("CVE-"):
                return alias
        return None

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
