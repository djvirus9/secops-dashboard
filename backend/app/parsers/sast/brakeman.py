import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class BrakemanParser(BaseParser):
    name = "brakeman"
    display_name = "Brakeman"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Static analysis security scanner for Ruby on Rails"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "warnings" in data and "scan_info" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for warning in data.get("warnings", []):
            confidence = warning.get("confidence", "Medium")
            if confidence == "High":
                severity = Severity.HIGH
            elif confidence == "Medium":
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            
            finding = ParsedFinding(
                title=f"{warning.get('warning_type', 'Unknown')}: {warning.get('message', '')}",
                severity=severity,
                tool="brakeman",
                description=warning.get("message", ""),
                asset=warning.get("file", "unknown"),
                file_path=warning.get("file"),
                line_number=warning.get("line"),
                recommendation=warning.get("link", ""),
                references=[warning.get("link")] if warning.get("link") else [],
                tags=[warning.get("warning_type", ""), warning.get("warning_code", "")],
                raw_data=warning,
            )
            findings.append(finding)
        
        return findings
