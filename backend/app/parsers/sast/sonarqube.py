import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SonarQubeParser(BaseParser):
    name = "sonarqube"
    display_name = "SonarQube"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Continuous code quality and security analysis"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "issues" in data or "hotspots" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for issue in data.get("issues", []):
            severity_map = {
                "BLOCKER": Severity.CRITICAL,
                "CRITICAL": Severity.HIGH,
                "MAJOR": Severity.MEDIUM,
                "MINOR": Severity.LOW,
                "INFO": Severity.INFO,
            }
            severity = severity_map.get(issue.get("severity", "MINOR"), Severity.LOW)
            
            component = issue.get("component", "")
            file_path = component.split(":")[-1] if ":" in component else component
            
            finding = ParsedFinding(
                title=issue.get("rule", "Unknown Rule"),
                severity=severity,
                tool="sonarqube",
                description=issue.get("message", ""),
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=issue.get("line") or issue.get("textRange", {}).get("startLine"),
                tags=[issue.get("type", ""), issue.get("rule", "")],
                raw_data=issue,
            )
            findings.append(finding)
        
        for hotspot in data.get("hotspots", []):
            finding = ParsedFinding(
                title=hotspot.get("securityCategory", "Security Hotspot"),
                severity=Severity.MEDIUM,
                tool="sonarqube",
                description=hotspot.get("message", ""),
                asset=hotspot.get("component", "unknown").split(":")[-1],
                file_path=hotspot.get("component", "").split(":")[-1],
                line_number=hotspot.get("line"),
                tags=["hotspot", hotspot.get("vulnerabilityProbability", "")],
                raw_data=hotspot,
            )
            findings.append(finding)
        
        return findings
