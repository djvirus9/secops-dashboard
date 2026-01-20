import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class BanditParser(BaseParser):
    name = "bandit"
    display_name = "Bandit"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Security linter for Python code"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and "generated_at" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data.get("results", []):
            cwe_id = None
            cwe_data = result.get("issue_cwe", {})
            if cwe_data and isinstance(cwe_data, dict):
                cwe_id = cwe_data.get("id")
            
            finding = ParsedFinding(
                title=f"{result.get('test_id', 'B000')}: {result.get('test_name', 'Unknown')}",
                severity=Severity.normalize(result.get("issue_severity", "LOW")),
                tool="bandit",
                description=result.get("issue_text", ""),
                asset=result.get("filename", "unknown"),
                file_path=result.get("filename"),
                line_number=result.get("line_number"),
                cwe_id=cwe_id,
                tags=[result.get("test_id", "")] if result.get("test_id") else [],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
