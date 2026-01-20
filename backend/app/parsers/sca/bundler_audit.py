import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class BundlerAuditParser(BaseParser):
    name = "bundler_audit"
    display_name = "Bundler-Audit"
    category = ScannerCategory.SCA
    file_types = ["txt", "json"]
    description = "Ruby Bundler dependency vulnerability scanner"

    def can_parse(self, content: str) -> bool:
        if "Insecure Source URI" in content or "Name:" in content and "Version:" in content and "CVE" in content:
            return True
        try:
            data = json.loads(content)
            return "results" in data or "vulnerabilities" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                for vuln in data.get("results", data.get("vulnerabilities", [])):
                    findings.append(ParsedFinding(
                        title=vuln.get("title", vuln.get("advisory", {}).get("title", "Bundler-Audit Finding")),
                        description=vuln.get("description", vuln.get("advisory", {}).get("description", "")),
                        severity=self._map_severity(vuln.get("criticality", "medium")),
                        tool=self.name,
                        asset=f"{vuln.get('gem', {}).get('name', 'unknown')}@{vuln.get('gem', {}).get('version', '')}",
                        cve=vuln.get("cve", vuln.get("advisory", {}).get("cve")),
                        raw_data=vuln
                    ))
            else:
                current = {}
                for line in content.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("Name:"):
                        current["name"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        current["version"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Title:"):
                        current["title"] = line.split(":", 1)[1].strip()
                    elif line.startswith("CVE:"):
                        current["cve"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Criticality:"):
                        current["severity"] = line.split(":", 1)[1].strip()
                    elif line.startswith("URL:"):
                        current["url"] = line.split(":", 1)[1].strip()
                    elif not line and current.get("name"):
                        findings.append(ParsedFinding(
                            title=current.get("title", "Bundler-Audit Finding"),
                            description=f"Vulnerable gem: {current.get('name')}@{current.get('version', '')}",
                            severity=self._map_severity(current.get("severity", "medium")),
                            tool=self.name,
                            asset=f"{current.get('name', 'unknown')}@{current.get('version', '')}",
                            cve=current.get("cve"),
                            raw_data=current
                        ))
                        current = {}
                if current.get("name"):
                    findings.append(ParsedFinding(
                        title=current.get("title", "Bundler-Audit Finding"),
                        description=f"Vulnerable gem: {current.get('name')}@{current.get('version', '')}",
                        severity=self._map_severity(current.get("severity", "medium")),
                        tool=self.name,
                        asset=f"{current.get('name', 'unknown')}@{current.get('version', '')}",
                        cve=current.get("cve"),
                        raw_data=current
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "unknown": "medium"}
        return mapping.get(str(sev).lower(), "medium")
