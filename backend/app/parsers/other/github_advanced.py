import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class GitHubAdvancedSecurityParser(BaseParser):
    name = "github_advanced_security"
    display_name = "GitHub Advanced Security"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "GitHub Advanced Security (code scanning, secret scanning, Dependabot)"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "rule" in data[0] and "tool" in data[0] or "secret_type" in data[0]
            return "number" in data and "state" in data and "rule" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            alerts = data if isinstance(data, list) else [data]
            for alert in alerts:
                if "secret_type" in alert:
                    findings.append(ParsedFinding(
                        title=f"Secret Detected: {alert.get('secret_type_display_name', alert.get('secret_type', 'Unknown'))}",
                        description=f"Secret found in {alert.get('locations_url', 'repository')}",
                        severity="high",
                        tool=self.name,
                        asset=alert.get("repository", {}).get("full_name", "unknown"),
                        raw_data=alert
                    ))
                elif "rule" in alert:
                    rule = alert.get("rule", {})
                    findings.append(ParsedFinding(
                        title=rule.get("description", rule.get("name", rule.get("id", "GitHub Code Scanning Alert"))),
                        description=alert.get("most_recent_instance", {}).get("message", {}).get("text", ""),
                        severity=self._map_severity(rule.get("security_severity_level", rule.get("severity", "medium"))),
                        tool=self.name,
                        asset=alert.get("most_recent_instance", {}).get("location", {}).get("path", "unknown"),
                        cwe=self._extract_cwe(rule.get("tags", [])),
                        raw_data=alert
                    ))
                elif "security_advisory" in alert:
                    advisory = alert.get("security_advisory", {})
                    findings.append(ParsedFinding(
                        title=advisory.get("summary", "Dependabot Alert"),
                        description=advisory.get("description", ""),
                        severity=self._map_severity(advisory.get("severity", "medium")),
                        tool=self.name,
                        asset=alert.get("dependency", {}).get("package", {}).get("name", "unknown"),
                        cve=advisory.get("cve_id"),
                        raw_data=alert
                    ))
        except:
            pass
        return findings

    def _extract_cwe(self, tags: list) -> str | None:
        for tag in tags:
            if tag.startswith("cwe-") or tag.startswith("CWE-"):
                return tag
        return None

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "warning": "medium", "note": "info", "error": "high"}
        return mapping.get(str(sev).lower(), "medium")
