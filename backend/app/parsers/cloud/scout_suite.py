import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ScoutSuiteParser(BaseParser):
    name = "scout-suite"
    display_name = "Scout Suite"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "Multi-cloud security auditing tool"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "services" in data and "provider_code" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        provider = data.get("provider_code", "cloud")
        
        for service_name, service_data in data.get("services", {}).items():
            for finding_key, finding_data in service_data.get("findings", {}).items():
                if not finding_data.get("flagged_items", 0):
                    continue
                
                level = finding_data.get("level", "warning")
                severity_map = {
                    "danger": Severity.HIGH,
                    "warning": Severity.MEDIUM,
                    "info": Severity.LOW,
                }
                
                for item in finding_data.get("items", []):
                    finding = ParsedFinding(
                        title=finding_data.get("description", finding_key),
                        severity=severity_map.get(level, Severity.MEDIUM),
                        tool="scout-suite",
                        description=finding_data.get("rationale", ""),
                        asset=item if isinstance(item, str) else str(item),
                        recommendation=finding_data.get("remediation", ""),
                        references=finding_data.get("references", []),
                        tags=[provider, service_name, finding_key],
                        raw_data={"finding": finding_data, "item": item},
                    )
                    findings.append(finding)
        
        return findings
