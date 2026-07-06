import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _map_sev(val) -> str:
    return _SEVERITY_MAP.get((val or "").lower(), "info")


@ParserRegistry.register
class XygeniParser(BaseParser):
    name = "xygeni"
    display_name = "Xygeni"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "Xygeni supply chain security platform"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and isinstance(data.get("metadata"), dict)
                and "scanType" in data["metadata"]
            )
        except Exception:
            return False

    def _parse_sast(self, data: dict) -> List[ParsedFinding]:
        findings = []
        for vuln in data.get("vulnerabilities") or []:
            location = vuln.get("location") or {}
            file_path = location.get("filepath")
            line = location.get("beginLine")
            description = vuln.get("explanation", "")
            code = location.get("code", "")
            if code:
                description += f"\n\n```\n{code}\n```"
            findings.append(ParsedFinding(
                title=str(vuln.get("detector") or "Xygeni SAST Finding"),
                severity=Severity.normalize(_map_sev(vuln.get("severity"))),
                tool=self.name,
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=int(line) if line else None,
                raw_data=vuln,
            ))
        return findings

    def _parse_sca(self, data: dict) -> List[ParsedFinding]:
        findings = []
        for dep in data.get("dependencies") or []:
            comp_name = dep.get("name", "")
            comp_version = dep.get("version", "")
            for vuln in dep.get("vulnerabilities") or []:
                cve = vuln.get("cve") or vuln.get("id", "")
                title = cve or "Xygeni SCA Finding"
                fixed = vuln.get("fixedVersion")
                recommendation = f"Upgrade {comp_name} to {fixed} or later." if fixed else ""
                cvss = vuln.get("overallCvssScore")
                try:
                    cvss_score = float(cvss) if cvss and cvss >= 0 else None
                except (TypeError, ValueError):
                    cvss_score = None
                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(_map_sev(vuln.get("severity"))),
                    tool=self.name,
                    description=str(vuln.get("description", "")),
                    asset=f"{comp_name}:{comp_version}" if comp_name else "unknown",
                    recommendation=recommendation,
                    cve_id=cve if cve.upper().startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    raw_data=vuln,
                ))
        return findings

    def _parse_secrets(self, data: dict) -> List[ParsedFinding]:
        findings = []
        groups = {}
        for secret in data.get("secrets") or []:
            key = secret.get("uniqueHash") or secret.get("issueId") or id(secret)
            groups.setdefault(key, []).append(secret)
        for occurrences in groups.values():
            secret = occurrences[0]
            location = secret.get("location") or {}
            filepath = location.get("filepath", "")
            secret_type = secret.get("type") or secret.get("detector") or "secret"
            filename_part = filepath.rsplit("/", 1)[-1] if filepath else "unknown file"
            description = secret.get("description", "")
            code = location.get("code", "")
            if code:
                description += f"\n\n```\n{code}\n```"
            findings.append(ParsedFinding(
                title=f"{secret_type} secret detected in {filename_part}",
                severity=Severity.normalize(_map_sev(secret.get("severity"))),
                tool=self.name,
                description=description,
                asset=filepath or "unknown",
                file_path=filepath or None,
                recommendation=f"Rotate this {secret_type} secret immediately.",
                raw_data=secret,
            ))
        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        try:
            data = json.loads(content)
            metadata = data.get("metadata") or {}
            scan_type = str(metadata.get("scanType", "")).lower()
            if scan_type == "sast":
                return self._parse_sast(data)
            if scan_type == "deps":
                return self._parse_sca(data)
            if scan_type == "secrets":
                return self._parse_secrets(data)
            # Unknown scan type — return empty
        except Exception:
            pass
        return []
