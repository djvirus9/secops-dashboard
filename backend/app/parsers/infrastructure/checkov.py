import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CheckovParser(BaseParser):
    name = "checkov"
    display_name = "Checkov"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Infrastructure as Code security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return len(data) > 0 and "check_type" in data[0]
            return "check_type" in data or "passed_checks" in data or "failed_checks" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if isinstance(data, list):
            for check_result in data:
                findings.extend(self._parse_check_result(check_result))
        else:
            findings.extend(self._parse_check_result(data))
        
        return findings
    
    def _parse_check_result(self, data: dict) -> List[ParsedFinding]:
        findings = []
        check_type = data.get("check_type", "")
        
        for check in data.get("results", {}).get("failed_checks", []):
            guideline = check.get("guideline", "")
            
            cwe_id = None
            cwe_ref = check.get("check_class", "")
            
            finding = ParsedFinding(
                title=f"{check.get('check_id', 'CKV')}: {check.get('check_name', 'Unknown Check')}",
                severity=Severity.normalize(check.get("severity", "MEDIUM")),
                tool="checkov",
                description=check.get("check_name", ""),
                asset=check.get("resource", check.get("file_path", "unknown")),
                file_path=check.get("file_path"),
                line_number=check.get("file_line_range", [None])[0],
                recommendation=guideline,
                references=[guideline] if guideline and guideline.startswith("http") else [],
                tags=[check_type, check.get("check_id", "")],
                raw_data=check,
            )
            findings.append(finding)
        
        return findings
