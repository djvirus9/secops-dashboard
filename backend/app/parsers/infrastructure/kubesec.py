import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class KubesecParser(BaseParser):
    name = "kubesec"
    display_name = "Kubesec"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Kubernetes resource security analyzer"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "scoring" in data[0] or "object" in data[0]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data:
            object_info = result.get("object", "unknown")
            if isinstance(object_info, dict):
                asset = f"{object_info.get('kind', 'Unknown')}/{object_info.get('name', 'unknown')}"
            else:
                asset = str(object_info)
            
            for critical in result.get("scoring", {}).get("critical", []):
                finding = ParsedFinding(
                    title=critical.get("id", "Critical Security Issue"),
                    severity=Severity.CRITICAL,
                    tool="kubesec",
                    description=critical.get("reason", ""),
                    asset=asset,
                    recommendation=critical.get("selector", ""),
                    tags=["kubernetes", "critical"],
                    raw_data=critical,
                )
                findings.append(finding)
            
            for adv in result.get("scoring", {}).get("advise", []):
                finding = ParsedFinding(
                    title=adv.get("id", "Security Advice"),
                    severity=Severity.MEDIUM,
                    tool="kubesec",
                    description=adv.get("reason", ""),
                    asset=asset,
                    recommendation=adv.get("selector", ""),
                    tags=["kubernetes", "advise"],
                    raw_data=adv,
                )
                findings.append(finding)
        
        return findings
