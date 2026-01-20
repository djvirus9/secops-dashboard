import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CrashtestParser(BaseParser):
    name = "crashtest"
    display_name = "Crashtest Security"
    category = ScannerCategory.DAST
    file_types = ["json", "xml"]
    description = "Crashtest Security SaaS vulnerability scanner"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "crashtest" in str(data).lower() or "scan_result" in data
        except:
            return "crashtest" in content.lower()

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                vulns = data.get("vulnerabilities", data.get("findings", data.get("scan_result", {}).get("vulnerabilities", [])))
                for vuln in vulns:
                    findings.append(ParsedFinding(
                        title=vuln.get("name", vuln.get("title", "Crashtest Finding")),
                        description=vuln.get("description", vuln.get("details", "")),
                        severity=self._map_severity(vuln.get("severity", vuln.get("risk", "medium"))),
                        tool=self.name,
                        asset=vuln.get("url", vuln.get("target", "unknown")),
                        cwe=vuln.get("cwe"),
                        cvss_score=vuln.get("cvss"),
                        raw_data=vuln
                    ))
            else:
                root = ET.fromstring(content)
                for vuln in root.findall(".//vulnerability") or root.findall(".//finding"):
                    name_el = vuln.find("name") or vuln.find("title")
                    findings.append(ParsedFinding(
                        title=name_el.text if name_el is not None else "Crashtest Finding",
                        description=vuln.findtext("description", ""),
                        severity=self._map_severity(vuln.findtext("severity", "medium")),
                        tool=self.name,
                        asset=vuln.findtext("url", "unknown"),
                        raw_data={"xml": True}
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")
