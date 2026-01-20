import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TerrascanParser(BaseParser):
    name = "terrascan"
    display_name = "Terrascan"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Accurics Terrascan IaC security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and "violated_policies" in str(data)[:500]
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        results = data.get("results", {})
        
        for policy in results.get("violated_policies", []):
            finding = ParsedFinding(
                title=f"{policy.get('rule_id', 'unknown')}: {policy.get('rule_name', policy.get('description', 'Policy Violation'))}",
                severity=Severity.normalize(policy.get("severity", "MEDIUM")),
                tool="terrascan",
                description=policy.get("description", ""),
                asset=policy.get("resource_name", policy.get("file", "unknown")),
                file_path=policy.get("file"),
                line_number=policy.get("line"),
                recommendation=policy.get("remediation", ""),
                references=[policy.get("reference_id", "")] if policy.get("reference_id") else [],
                tags=["iac", policy.get("category", ""), policy.get("resource_type", "")],
                raw_data=policy,
            )
            findings.append(finding)
        
        return findings
