import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class NiktoParser(BaseParser):
    name = "nikto"
    display_name = "Nikto"
    category = ScannerCategory.DAST
    file_types = ["json", "xml"]
    description = "Web server vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "vulnerabilities" in data or "host" in data
            elif content.strip().startswith("<"):
                return "niktoscan" in content.lower()[:500]
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
        
        host = data.get("host", data.get("ip", "unknown"))
        port = data.get("port", "80")
        
        for vuln in data.get("vulnerabilities", []):
            finding = ParsedFinding(
                title=vuln.get("msg", "Nikto Finding")[:100],
                severity=Severity.MEDIUM,
                tool="nikto",
                description=vuln.get("msg", ""),
                asset=f"{host}:{port}",
                references=[vuln.get("references", "")] if vuln.get("references") else [],
                tags=["nikto", vuln.get("id", "")],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        findings = []
        
        for scan_details in root.findall(".//scandetails"):
            host = scan_details.get("targetip", scan_details.get("targethostname", "unknown"))
            port = scan_details.get("targetport", "80")
            
            for item in scan_details.findall(".//item"):
                finding = ParsedFinding(
                    title=item.findtext("description", "Nikto Finding")[:100],
                    severity=Severity.MEDIUM,
                    tool="nikto",
                    description=item.findtext("description", ""),
                    asset=f"{host}:{port}",
                    tags=["nikto", item.get("id", "")],
                    raw_data={},
                )
                findings.append(finding)
        
        return findings
