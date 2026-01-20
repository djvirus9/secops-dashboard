import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class GitGuardianParser(BaseParser):
    name = "gitguardian"
    display_name = "GitGuardian"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "GitGuardian ggshield secrets detection"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return "policy_breaks" in data or "secrets_engine_version" in data or "entities_with_incidents" in data
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            incidents = data.get("policy_breaks", data.get("entities_with_incidents", []))
            if isinstance(data, dict) and "scans" in data:
                for scan in data["scans"]:
                    incidents.extend(scan.get("policy_breaks", []))
            for incident in incidents:
                matches = incident.get("matches", [])
                for match in matches:
                    findings.append(ParsedFinding(
                        title=f"Secret Detected: {incident.get('break_type', incident.get('type', 'Secret'))}",
                        description=f"GitGuardian detected {incident.get('policy', 'a secret')} in code",
                        severity=self._map_severity(incident.get("severity", "high")),
                        tool=self.name,
                        asset=match.get("filename", incident.get("filename", "unknown")),
                        raw_data={"incident": incident, "match": match}
                    ))
                if not matches:
                    findings.append(ParsedFinding(
                        title=f"Secret Detected: {incident.get('break_type', incident.get('type', 'Secret'))}",
                        description=f"GitGuardian detected {incident.get('policy', 'a secret')} in code",
                        severity=self._map_severity(incident.get("severity", "high")),
                        tool=self.name,
                        asset=incident.get("filename", "unknown"),
                        raw_data=incident
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        return "high" if sev else "high"
