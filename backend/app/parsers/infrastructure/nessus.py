import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class NessusParser(BaseParser):
    name = "nessus"
    display_name = "Nessus"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["xml", "json", "nessus"]
    description = "Tenable Nessus vulnerability scanner"

    def can_parse(self, content: str) -> bool:
        return "NessusClientData" in content or "nessus" in content.lower() or "ReportHost" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for host in root.findall(".//ReportHost"):
                    host_name = host.get("name", "unknown")
                    for item in host.findall(".//ReportItem"):
                        severity = item.get("severity", "0")
                        if int(severity) > 0:
                            plugin_name = item.get("pluginName", "Nessus Finding")
                            findings.append(ParsedFinding(
                                title=plugin_name,
                                description=item.findtext("description", item.findtext("synopsis", "")),
                                severity=self._map_severity(severity),
                                tool=self.name,
                                asset=f"{host_name}:{item.get('port', '')}",
                                cve=self._extract_cve(item),
                                cvss_score=self._extract_cvss(item),
                                raw_data={"plugin_id": item.get("pluginID"), "host": host_name}
                            ))
            else:
                data = json.loads(content)
                vulns = data.get("vulnerabilities", [])
                for vuln in vulns:
                    findings.append(ParsedFinding(
                        title=vuln.get("plugin_name", "Nessus Finding"),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", "0")),
                        tool=self.name,
                        asset=vuln.get("host_name", "unknown"),
                        cve=vuln.get("cve"),
                        cvss_score=vuln.get("cvss_base_score"),
                        raw_data=vuln
                    ))
        except:
            pass
        return findings

    def _extract_cve(self, item) -> str | None:
        cve_el = item.find("cve")
        return cve_el.text if cve_el is not None else None

    def _extract_cvss(self, item) -> float | None:
        cvss_el = item.find("cvss3_base_score") or item.find("cvss_base_score")
        try:
            return float(cvss_el.text) if cvss_el is not None else None
        except:
            return None

    def _map_severity(self, sev: str) -> str:
        try:
            level = int(sev)
            if level >= 4: return "critical"
            if level >= 3: return "high"
            if level >= 2: return "medium"
            if level >= 1: return "low"
            return "info"
        except:
            return "medium"
