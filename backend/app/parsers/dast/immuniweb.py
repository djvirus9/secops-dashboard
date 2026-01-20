import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class ImmuniwebParser(BaseParser):
    name = "immuniweb"
    display_name = "Immuniweb"
    category = ScannerCategory.DAST
    file_types = ["xml", "json"]
    description = "Immuniweb web security scanner"

    def can_parse(self, content: str) -> bool:
        return "immuniweb" in content.lower() or "ImmuniWeb" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for vuln in root.findall(".//vulnerability") or root.findall(".//finding"):
                    name = vuln.findtext("name") or vuln.findtext("title") or "Immuniweb Finding"
                    findings.append(ParsedFinding(
                        title=name,
                        description=vuln.findtext("description", ""),
                        severity=self._map_severity(vuln.findtext("severity", "medium")),
                        tool=self.name,
                        asset=vuln.findtext("url", vuln.findtext("target", "unknown")),
                        cwe=vuln.findtext("cwe"),
                        raw_data={"xml": True}
                    ))
            else:
                data = json.loads(content)
                vulns = data.get("vulnerabilities", data.get("findings", []))
                for vuln in vulns:
                    findings.append(ParsedFinding(
                        title=vuln.get("name", vuln.get("title", "Immuniweb Finding")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", "medium")),
                        tool=self.name,
                        asset=vuln.get("url", vuln.get("target", "unknown")),
                        cwe=vuln.get("cwe"),
                        raw_data=vuln
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")
