import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PHPStanParser(BaseParser):
    name = "phpstan"
    display_name = "PHPStan"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "PHP static analysis tool"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "totals" in data and "files" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for file_path, file_data in data.get("files", {}).items():
            for message in file_data.get("messages", []):
                finding = ParsedFinding(
                    title=message.get("message", "PHPStan Issue")[:100],
                    severity=Severity.MEDIUM,
                    tool="phpstan",
                    description=message.get("message", ""),
                    asset=file_path,
                    file_path=file_path,
                    line_number=message.get("line"),
                    tags=["phpstan"],
                    raw_data=message,
                )
                findings.append(finding)
        
        return findings
