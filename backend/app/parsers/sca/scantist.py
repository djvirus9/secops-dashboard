import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ScantistParser(BaseParser):
    name = "scantist"
    display_name = "Scantist"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Scantist SCA vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or len(data) == 0:
                return False
            first = data[0]
            return isinstance(first, dict) and "Public ID" in first and "Library" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        for vuln in data:
            if not isinstance(vuln, dict):
                continue

            vuln_id = vuln.get("Public ID", "")
            library = vuln.get("Library", "unknown")
            library_version = vuln.get("Library Version", "unknown")

            dedup_key = f"{vuln_id}|{library}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            title = f"{vuln_id}|{library}" if vuln_id else library
            severity_raw = vuln.get("Score", "info")

            # Scantist uses numeric score or severity label
            severity = self._normalize_scantist_severity(severity_raw)

            cve_id = vuln_id if vuln_id and vuln_id.startswith("CVE-") else None

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity),
                tool="scantist",
                description=vuln.get("Description", ""),
                asset=library,
                file_path=vuln.get("File Path", None) or None,
                cve_id=cve_id,
                cwe_id=1035,
                recommendation=str(vuln.get("Patched Version", "")) or "",
                references=[vuln.get("references")] if vuln.get("references") else [],
                tags=["scantist", library],
                raw_data=vuln,
            ))

        return findings

    def _normalize_scantist_severity(self, value) -> str:
        if value is None:
            return "info"
        try:
            score = float(value)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score >= 0.1:
                return "low"
            return "info"
        except (ValueError, TypeError):
            return str(value).lower()
