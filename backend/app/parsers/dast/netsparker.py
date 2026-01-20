import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class NetsparkerParser(BaseParser):
    name = "netsparker"
    display_name = "Netsparker / Invicti"
    category = ScannerCategory.DAST
    file_types = ["json", "xml"]
    description = "Enterprise web application security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "vulnerabilities" in data and "target" in data
            elif content.strip().startswith("<"):
                return "netsparker" in content.lower()[:1000] or "invicti" in content.lower()[:1000]
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
        
        target = data.get("target", {}).get("url", "unknown")
        
        for vuln in data.get("vulnerabilities", []):
            severity_str = vuln.get("severity", "Information")
            severity_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
                "Information": Severity.INFO,
                "BestPractice": Severity.INFO,
            }
            
            cwe_id = None
            if vuln.get("classification", {}).get("cwe"):
                try:
                    cwe_id = int(vuln["classification"]["cwe"])
                except:
                    pass
            
            finding = ParsedFinding(
                title=vuln.get("name", vuln.get("type", "Unknown")),
                severity=severity_map.get(severity_str, Severity.INFO),
                tool="netsparker",
                description=vuln.get("description", ""),
                asset=vuln.get("url", target),
                cwe_id=cwe_id,
                recommendation=vuln.get("remedy", ""),
                tags=["netsparker", vuln.get("type", "")],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        findings = []
        
        target = root.findtext(".//target/url", "unknown")
        
        for vuln in root.findall(".//vulnerability"):
            severity_str = vuln.findtext("severity", "Information")
            severity_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
                "Information": Severity.INFO,
            }
            
            cwe_id = None
            cwe_text = vuln.findtext(".//classification/cwe")
            if cwe_text:
                try:
                    cwe_id = int(cwe_text)
                except:
                    pass
            
            finding = ParsedFinding(
                title=vuln.findtext("name", vuln.findtext("type", "Unknown")),
                severity=severity_map.get(severity_str, Severity.INFO),
                tool="netsparker",
                description=vuln.findtext("description", ""),
                asset=vuln.findtext("url", target),
                cwe_id=cwe_id,
                recommendation=vuln.findtext("remedy", ""),
                tags=["netsparker"],
                raw_data={},
            )
            findings.append(finding)
        
        return findings
