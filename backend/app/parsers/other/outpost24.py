import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class Outpost24Parser(BaseParser):
    name = "outpost24"
    display_name = "Outpost24"
    category = ScannerCategory.OTHER
    file_types = ["xml", "json"]
    description = "Outpost24 vulnerability management"

    def can_parse(self, content: str) -> bool:
        return "outpost24" in content.lower() or "Outpost24" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for vuln in root.findall(".//vulnerability") or root.findall(".//finding"):
                    findings.append(ParsedFinding(
                        title=vuln.findtext("name", vuln.findtext("title", "Outpost24 Finding")),
                        description=vuln.findtext("description", ""),
                        severity=self._map_severity(vuln.findtext("severity", vuln.findtext("risk", "medium"))),
                        tool=self.name,
                        asset=vuln.findtext("host", vuln.findtext("target", "unknown")),
                        cve=vuln.findtext("cve"),
                        raw_data={"xml": True}
                    ))
            else:
                data = json.loads(content)
                vulns = data.get("vulnerabilities", data.get("findings", []))
                for vuln in vulns:
                    findings.append(ParsedFinding(
                        title=vuln.get("name", vuln.get("title", "Outpost24 Finding")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", vuln.get("risk", "medium"))),
                        tool=self.name,
                        asset=vuln.get("host", vuln.get("target", "unknown")),
                        cve=vuln.get("cve"),
                        raw_data=vuln
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        try:
            level = int(sev)
            if level >= 4: return "critical"
            if level >= 3: return "high"
            if level >= 2: return "medium"
            return "low"
        except:
            mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            return mapping.get(str(sev).lower(), "medium")
