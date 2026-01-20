import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ESLintParser(BaseParser):
    name = "eslint"
    display_name = "ESLint"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "JavaScript/TypeScript linting with security rules"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "filePath" in data[0] and "messages" in data[0]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for file_result in data:
            file_path = file_result.get("filePath", "unknown")
            
            for message in file_result.get("messages", []):
                severity_num = message.get("severity", 1)
                if severity_num == 2:
                    severity = Severity.HIGH
                elif severity_num == 1:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                
                finding = ParsedFinding(
                    title=message.get("ruleId", "eslint-rule"),
                    severity=severity,
                    tool="eslint",
                    description=message.get("message", ""),
                    asset=file_path,
                    file_path=file_path,
                    line_number=message.get("line"),
                    recommendation=message.get("fix", {}).get("text", "") if message.get("fix") else "",
                    tags=["eslint", message.get("ruleId", "")] if message.get("ruleId") else ["eslint"],
                    raw_data=message,
                )
                findings.append(finding)
        
        return findings
