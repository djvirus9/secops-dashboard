import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AcunetixParser(BaseParser):
    name = "acunetix"
    display_name = "Acunetix"
    category = ScannerCategory.DAST
    file_types = ["json", "xml"]
    description = "Acunetix web vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "vulnerabilities" in data or "scans" in data
            elif content.strip().startswith("<"):
                return "acunetix" in content.lower()[:500] or "ScanGroup" in content[:500]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if content.strip().startswith("{"):
            return self._parse_json(content)
        else:
            return self._parse_xml(content)
    
    def _parse_json(self, content: str) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        vulns = data.get("vulnerabilities", [])
        
        for vuln in vulns:
            severity_num = vuln.get("severity", 1)
            severity_map = {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.INFO}
            
            finding = ParsedFinding(
                title=vuln.get("vt_name", vuln.get("name", "Unknown Vulnerability")),
                severity=severity_map.get(severity_num, Severity.INFO),
                tool="acunetix",
                description=vuln.get("description", ""),
                asset=vuln.get("affects_url", vuln.get("target", "unknown")),
                recommendation=vuln.get("recommendation", ""),
                tags=vuln.get("tags", []),
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        findings = []
        
        for report_item in root.findall(".//ReportItem"):
            severity_str = report_item.findtext("Severity", "informational")
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFO,
            }
            
            cwe_id = None
            cwe_text = report_item.findtext("CWE")
            if cwe_text:
                try:
                    cwe_id = int(cwe_text.replace("CWE-", ""))
                except:
                    pass
            
            finding = ParsedFinding(
                title=report_item.findtext("Name", "Unknown"),
                severity=severity_map.get(severity_str.lower(), Severity.INFO),
                tool="acunetix",
                description=report_item.findtext("Description", ""),
                asset=report_item.findtext("AffectedItem", report_item.findtext("Affects", "unknown")),
                cwe_id=cwe_id,
                recommendation=report_item.findtext("Recommendation", ""),
                tags=["acunetix"],
                raw_data={},
            )
            findings.append(finding)
        
        return findings
