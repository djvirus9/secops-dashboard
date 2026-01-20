import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class HadolintParser(BaseParser):
    name = "hadolint"
    display_name = "Hadolint"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Dockerfile linter"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "code" in data[0] and "message" in data[0]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data:
            level = result.get("level", "warning")
            severity_map = {
                "error": Severity.HIGH,
                "warning": Severity.MEDIUM,
                "info": Severity.LOW,
                "style": Severity.INFO,
            }
            
            finding = ParsedFinding(
                title=f"{result.get('code', 'DL0000')}: {result.get('message', 'Dockerfile Issue')[:80]}",
                severity=severity_map.get(level, Severity.MEDIUM),
                tool="hadolint",
                description=result.get("message", ""),
                asset=result.get("file", "Dockerfile"),
                file_path=result.get("file", "Dockerfile"),
                line_number=result.get("line"),
                tags=["dockerfile", result.get("code", "")],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
