import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SemgrepParser(BaseParser):
    name = "semgrep"
    display_name = "Semgrep"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Lightweight static analysis for many languages"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and isinstance(data.get("results"), list)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            
            severity_str = extra.get("severity", "INFO")
            
            cwe_ids = metadata.get("cwe", [])
            cwe_id = None
            if cwe_ids and isinstance(cwe_ids, list):
                first_cwe = cwe_ids[0] if cwe_ids else ""
                if "CWE-" in str(first_cwe):
                    try:
                        cwe_id = int(str(first_cwe).split("CWE-")[1].split(":")[0].split(" ")[0])
                    except:
                        pass
            
            finding = ParsedFinding(
                title=result.get("check_id", "Unknown Check"),
                severity=Severity.normalize(severity_str),
                tool="semgrep",
                description=extra.get("message", ""),
                asset=result.get("path", "unknown"),
                file_path=result.get("path"),
                line_number=result.get("start", {}).get("line"),
                cwe_id=cwe_id,
                recommendation=metadata.get("fix", ""),
                references=metadata.get("references", []),
                tags=metadata.get("category", "").split(",") if metadata.get("category") else [],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
