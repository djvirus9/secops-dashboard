import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TrustwaveFusionAPIParser(BaseParser):
    name = "trustwave_fusion_api"
    display_name = "Trustwave Fusion API"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Trustwave Fusion API scan report (JSON)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and "items" in data
                and isinstance(data["items"], list)
                and len(data["items"]) > 0
                and "location" in data["items"][0]
                and "kb" in data["items"][0]
            )
        except Exception:
            return False

    def _extract_asset(self, location: dict) -> str:
        if location.get("url") and location["url"] != "None":
            return location["url"]
        protocol = location.get("applicationProtocol", "")
        if location.get("domain") and location["domain"] != "None":
            host = location["domain"]
        elif location.get("ip") and location["ip"] != "None":
            host = location["ip"]
        else:
            return "unknown"
        port = location.get("port", "")
        if protocol and protocol != "None":
            return f"{protocol}://{host}:{port}" if port and port != "None" else f"{protocol}://{host}"
        return f"{host}:{port}" if port and port != "None" else host

    def _convert_severity(self, num_severity: int) -> str:
        """Trustwave Fusion uses negative integer severity scores."""
        if num_severity >= -10:
            return "low"
        if -11 >= num_severity > -26:
            return "medium"
        if num_severity <= -26:
            return "high"
        return "info"

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        seen = {}
        for node in data.get("items", []):
            title = node.get("name", "Unknown")
            description = node.get("classification", "")
            location = node.get("location", {})
            asset = self._extract_asset(location)

            severity_raw = node.get("severity", "")
            # Try numeric severity first
            try:
                sev_num = int(severity_raw)
                severity_str = self._convert_severity(sev_num)
            except (ValueError, TypeError):
                severity_str = str(severity_raw).lower()

            kb = node.get("kb", {})
            cves = kb.get("cves", [])
            cve_id = None
            if cves and "CVE-NO-MATCH" not in cves:
                cve_id = cves[0] if cves[0].startswith("CVE-") else None

            dedup = f"{severity_str}|{title}|{description[:100]}"
            if dedup in seen:
                continue
            seen[dedup] = True

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="trustwave_fusion_api",
                description=description,
                asset=asset,
                cwe_id=None,
                cve_id=cve_id,
                cvss_score=None,
                recommendation="",
                raw_data=node,
            ))

        return findings
