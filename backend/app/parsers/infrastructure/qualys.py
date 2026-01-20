import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class QualysParser(BaseParser):
    name = "qualys"
    display_name = "Qualys"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["xml", "json", "csv"]
    description = "Qualys vulnerability management scanner"

    def can_parse(self, content: str) -> bool:
        return "QUALYS" in content.upper() or "qualys" in content.lower() or "QID" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for vuln in root.findall(".//VULN") or root.findall(".//HOST_VULN") or root.findall(".//vuln"):
                    qid = vuln.findtext("QID", "")
                    title = vuln.findtext("TITLE") or vuln.findtext("title") or f"QID {qid}"
                    findings.append(ParsedFinding(
                        title=title,
                        description=vuln.findtext("DIAGNOSIS") or vuln.findtext("diagnosis") or "",
                        severity=self._map_severity(vuln.findtext("SEVERITY") or vuln.findtext("severity") or "3"),
                        tool=self.name,
                        asset=vuln.findtext("IP") or vuln.findtext("HOST") or vuln.findtext("host") or "unknown",
                        cve=vuln.findtext("CVE_ID") or vuln.findtext("cve"),
                        raw_data={"qid": qid, "xml": True}
                    ))
            else:
                data = json.loads(content)
                vulns = data.get("vulnerabilities", data.get("host_list_vm_detection_output", {}).get("response", {}).get("HOST_LIST", {}).get("HOST", []))
                if not isinstance(vulns, list):
                    vulns = [vulns]
                for vuln in vulns:
                    detections = vuln.get("DETECTION_LIST", {}).get("DETECTION", [])
                    if not isinstance(detections, list):
                        detections = [detections]
                    host = vuln.get("IP", vuln.get("DNS", "unknown"))
                    for det in detections:
                        findings.append(ParsedFinding(
                            title=det.get("TITLE", f"QID {det.get('QID', 'Unknown')}"),
                            description=det.get("RESULTS", ""),
                            severity=self._map_severity(det.get("SEVERITY", "3")),
                            tool=self.name,
                            asset=host,
                            raw_data=det
                        ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        try:
            level = int(sev)
            if level >= 5: return "critical"
            if level >= 4: return "high"
            if level >= 3: return "medium"
            return "low"
        except:
            return "medium"
