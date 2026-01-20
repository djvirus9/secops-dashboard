import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ArachniParser(BaseParser):
    name = "arachni"
    display_name = "Arachni"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Web application security scanner framework"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "issues" in data and "sitemap" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for issue in data.get("issues", []):
            severity_str = issue.get("severity", "informational")
            severity_map = {
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFO,
            }
            
            cwe_id = None
            if issue.get("cwe"):
                try:
                    cwe_id = int(issue["cwe"])
                except:
                    pass
            
            finding = ParsedFinding(
                title=issue.get("name", "Unknown Issue"),
                severity=severity_map.get(severity_str.lower(), Severity.INFO),
                tool="arachni",
                description=issue.get("description", ""),
                asset=issue.get("vector", {}).get("url", issue.get("url", "unknown")),
                cwe_id=cwe_id,
                recommendation=issue.get("remedy_guidance", ""),
                references=issue.get("references", {}).values() if isinstance(issue.get("references"), dict) else [],
                tags=issue.get("tags", []),
                raw_data=issue,
            )
            findings.append(finding)
        
        return findings
