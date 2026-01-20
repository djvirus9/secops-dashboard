import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GitleaksParser(BaseParser):
    name = "gitleaks"
    display_name = "Gitleaks"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "Secret and credential scanner for git repositories"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "RuleID" in data[0] or "rule" in data[0] or "Secret" in data[0]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data:
            rule_id = result.get("RuleID") or result.get("rule", "unknown-secret")
            description = result.get("Description") or result.get("description", "Secret detected")
            file_path = result.get("File") or result.get("file", "unknown")
            line = result.get("StartLine") or result.get("line")
            
            secret_preview = result.get("Secret", "")[:20] + "..." if result.get("Secret") else ""
            
            finding = ParsedFinding(
                title=f"Secret Detected: {rule_id}",
                severity=Severity.HIGH,
                tool="gitleaks",
                description=f"{description}. Partial match: {secret_preview}",
                asset=file_path,
                file_path=file_path,
                line_number=line,
                tags=["secrets", "credentials", rule_id],
                raw_data={k: v for k, v in result.items() if k != "Secret"},
            )
            findings.append(finding)
        
        return findings
