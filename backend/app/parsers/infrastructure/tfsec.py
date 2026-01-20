import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TfsecParser(BaseParser):
    name = "tfsec"
    display_name = "tfsec"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Terraform static analysis security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and ("tfsec" in str(data).lower()[:100] or any("rule_id" in str(r) for r in data.get("results", [])[:3]))
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data.get("results", []):
            cwe_id = None
            links = result.get("links", [])
            
            finding = ParsedFinding(
                title=f"{result.get('rule_id', 'unknown')}: {result.get('rule_description', result.get('description', 'Security Issue'))}",
                severity=Severity.normalize(result.get("severity", "MEDIUM")),
                tool="tfsec",
                description=result.get("description", ""),
                asset=result.get("location", {}).get("filename", "unknown"),
                file_path=result.get("location", {}).get("filename"),
                line_number=result.get("location", {}).get("start_line"),
                recommendation=result.get("resolution", ""),
                references=links,
                tags=["terraform", result.get("rule_provider", ""), result.get("rule_id", "")],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
