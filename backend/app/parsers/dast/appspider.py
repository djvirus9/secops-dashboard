import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class AppSpiderParser(BaseParser):
    name = "appspider"
    display_name = "AppSpider (Rapid7)"
    category = ScannerCategory.DAST
    file_types = ["xml", "json"]
    description = "Rapid7 AppSpider dynamic application security testing"

    def can_parse(self, content: str) -> bool:
        return "AppSpider" in content or "VulnSummary" in content or "WebAppScan" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for vuln in root.findall(".//VulnSummary") or root.findall(".//Vuln") or root.findall(".//Finding"):
                    name_el = vuln.find("VulnType") or vuln.find("Name") or vuln.find("Title")
                    name = name_el.text if name_el is not None else "AppSpider Finding"
                    desc_el = vuln.find("Description") or vuln.find("Recommendation")
                    desc = desc_el.text if desc_el is not None else ""
                    sev_el = vuln.find("AttackScore") or vuln.find("Severity")
                    sev = sev_el.text if sev_el is not None else "medium"
                    url_el = vuln.find("AttackedUrl") or vuln.find("Url")
                    url = url_el.text if url_el is not None else "unknown"
                    findings.append(ParsedFinding(
                        title=name,
                        description=desc,
                        severity=self._map_severity(sev),
                        tool=self.name,
                        asset=url,
                        raw_data={"xml": True}
                    ))
            else:
                data = json.loads(content)
                for vuln in data.get("vulnerabilities", data.get("findings", [])):
                    findings.append(ParsedFinding(
                        title=vuln.get("vulnType", vuln.get("name", "AppSpider Finding")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", "medium")),
                        tool=self.name,
                        asset=vuln.get("url", vuln.get("attackedUrl", "unknown")),
                        cwe=vuln.get("cwe"),
                        raw_data=vuln
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        try:
            score = int(sev)
            if score >= 8: return "critical"
            if score >= 6: return "high"
            if score >= 4: return "medium"
            return "low"
        except:
            mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            return mapping.get(str(sev).lower(), "medium")
