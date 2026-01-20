import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class DockleParser(BaseParser):
    name = "dockle"
    display_name = "Dockle"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Container image linter for security"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "details" in data and "summary" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for detail in data.get("details", []):
            level = detail.get("level", "WARN")
            severity_map = {
                "FATAL": Severity.CRITICAL,
                "WARN": Severity.MEDIUM,
                "INFO": Severity.LOW,
                "SKIP": Severity.INFO,
                "PASS": Severity.INFO,
            }
            
            if level in ["PASS", "SKIP"]:
                continue
            
            for alert in detail.get("alerts", []):
                finding = ParsedFinding(
                    title=f"{detail.get('code', 'CIS-DI-0000')}: {detail.get('title', 'Container Security Issue')}",
                    severity=severity_map.get(level, Severity.MEDIUM),
                    tool="dockle",
                    description=alert,
                    asset=data.get("summary", {}).get("image", "unknown"),
                    tags=["container", "dockle", detail.get("code", "")],
                    raw_data={"detail": detail, "alert": alert},
                )
                findings.append(finding)
        
        return findings
