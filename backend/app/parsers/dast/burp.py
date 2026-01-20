import json
import xml.etree.ElementTree as ET
import base64
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class BurpParser(BaseParser):
    name = "burp"
    display_name = "Burp Suite"
    category = ScannerCategory.DAST
    file_types = ["json", "xml", "html"]
    description = "PortSwigger Burp Suite web security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "issue_events" in data or "issues" in data
            elif content.strip().startswith("<"):
                root = ET.fromstring(content)
                return root.tag == "issues" or "burp" in str(content).lower()[:500]
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
        
        issues = data.get("issue_events", data.get("issues", []))
        
        for issue in issues:
            issue_data = issue.get("issue", issue)
            
            severity_str = issue_data.get("severity", "information")
            severity_map = {
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "information": Severity.INFO,
                "info": Severity.INFO,
            }
            
            finding = ParsedFinding(
                title=issue_data.get("name", issue_data.get("type_index", "Unknown")),
                severity=severity_map.get(severity_str.lower(), Severity.INFO),
                tool="burp",
                description=issue_data.get("description", ""),
                asset=issue_data.get("origin", issue_data.get("host", "unknown")),
                recommendation=issue_data.get("remediation", ""),
                references=[issue_data.get("references", "")] if issue_data.get("references") else [],
                tags=["burp", str(issue_data.get("type_index", ""))],
                raw_data=issue_data,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        findings = []
        
        for issue in root.findall(".//issue"):
            severity_str = issue.findtext("severity", "information").lower()
            severity_map = {
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "information": Severity.INFO,
            }
            
            finding = ParsedFinding(
                title=issue.findtext("name", "Unknown Issue"),
                severity=severity_map.get(severity_str, Severity.INFO),
                tool="burp",
                description=issue.findtext("issueDetail", issue.findtext("issueBackground", "")),
                asset=issue.findtext("host", "unknown"),
                recommendation=issue.findtext("remediationBackground", ""),
                tags=["burp", issue.findtext("type", "")],
                raw_data={},
            )
            findings.append(finding)
        
        return findings
