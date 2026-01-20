import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class KICSParser(BaseParser):
    name = "kics"
    display_name = "KICS"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Checkmarx Infrastructure as Code security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "queries" in data and "kics_version" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for query in data.get("queries", []):
            query_name = query.get("query_name", "Unknown Query")
            query_id = query.get("query_id", "")
            severity_str = query.get("severity", "MEDIUM")
            description = query.get("description", "")
            
            cwe_id = None
            if query.get("cwe"):
                try:
                    cwe_id = int(query["cwe"])
                except:
                    pass
            
            for file_result in query.get("files", []):
                finding = ParsedFinding(
                    title=query_name,
                    severity=Severity.normalize(severity_str),
                    tool="kics",
                    description=description,
                    asset=file_result.get("file_name", "unknown"),
                    file_path=file_result.get("file_name"),
                    line_number=file_result.get("line"),
                    cwe_id=cwe_id,
                    recommendation=file_result.get("expected_value", ""),
                    tags=[query.get("platform", ""), query_id],
                    raw_data={"query": query, "file": file_result},
                )
                findings.append(finding)
        
        return findings
