import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GosecParser(BaseParser):
    name = "gosec"
    display_name = "Gosec"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Go security checker"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "Issues" in data or "Golang errors" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for issue in data.get("Issues", []):
            cwe_id = None
            cwe_data = issue.get("cwe", {})
            if cwe_data:
                cwe_id = int(cwe_data.get("id", 0)) if cwe_data.get("id") else None
            
            finding = ParsedFinding(
                title=f"{issue.get('rule_id', 'G000')}: {issue.get('details', 'Security Issue')}",
                severity=Severity.normalize(issue.get("severity", "MEDIUM")),
                tool="gosec",
                description=issue.get("details", ""),
                asset=issue.get("file", "unknown"),
                file_path=issue.get("file"),
                line_number=int(issue.get("line", 0)) if issue.get("line") else None,
                cwe_id=cwe_id,
                tags=[issue.get("rule_id", "")] if issue.get("rule_id") else [],
                raw_data=issue,
            )
            findings.append(finding)
        
        return findings
