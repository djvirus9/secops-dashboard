import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class BearerParser(BaseParser):
    name = "bearer"
    display_name = "Bearer CLI"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Code security and privacy analysis"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "findings" in data or ("high" in data and "critical" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        all_findings = []
        if "findings" in data:
            all_findings = data["findings"]
        else:
            for sev in ["critical", "high", "medium", "low", "warning"]:
                all_findings.extend(data.get(sev, []))
        
        for result in all_findings:
            cwe_ids = result.get("cwe_ids", [])
            cwe_id = int(cwe_ids[0].replace("CWE-", "")) if cwe_ids else None
            
            finding = ParsedFinding(
                title=result.get("title", result.get("rule_id", "Unknown")),
                severity=Severity.normalize(result.get("severity", "medium")),
                tool="bearer",
                description=result.get("description", ""),
                asset=result.get("filename", "unknown"),
                file_path=result.get("filename"),
                line_number=result.get("line_number"),
                cwe_id=cwe_id,
                recommendation=result.get("documentation_url", ""),
                references=[result.get("documentation_url")] if result.get("documentation_url") else [],
                tags=result.get("categories", []),
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
