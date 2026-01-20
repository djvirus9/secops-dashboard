import csv
from io import StringIO
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GenericCSVParser(BaseParser):
    name = "generic-csv"
    display_name = "Generic CSV"
    category = ScannerCategory.GENERIC
    file_types = ["csv"]
    description = "Generic CSV findings import"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        
        reader = csv.DictReader(StringIO(content))
        
        headers = {h.lower(): h for h in (reader.fieldnames or [])}
        
        for row in reader:
            finding = self._parse_row(row, headers)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _parse_row(self, row: dict, headers: dict) -> Optional[ParsedFinding]:
        title = self._get_field(row, headers, ["title", "name", "summary", "message", "vulnerability", "issue"])
        if not title:
            return None
        
        severity_str = self._get_field(row, headers, ["severity", "level", "risk", "priority"])
        
        description = self._get_field(row, headers, ["description", "details", "message", "info"])
        
        asset = self._get_field(row, headers, ["asset", "host", "target", "url", "file", "resource"])
        
        file_path = self._get_field(row, headers, ["file", "file_path", "path", "filename"])
        
        line = self._get_field(row, headers, ["line", "line_number", "linenumber"])
        line_number = int(line) if line and str(line).isdigit() else None
        
        cve = self._get_field(row, headers, ["cve", "cve_id", "vulnerability_id"])
        
        cwe = self._get_field(row, headers, ["cwe", "cwe_id"])
        cwe_id = None
        if cwe:
            try:
                cwe_id = int(str(cwe).replace("CWE-", ""))
            except:
                pass
        
        cvss = self._get_field(row, headers, ["cvss", "cvss_score", "score"])
        cvss_score = None
        if cvss:
            try:
                cvss_score = float(cvss)
            except:
                pass
        
        recommendation = self._get_field(row, headers, ["recommendation", "remediation", "fix", "solution"])
        
        return ParsedFinding(
            title=str(title)[:200],
            severity=Severity.normalize(severity_str) if severity_str else Severity.MEDIUM,
            tool="generic-csv",
            description=str(description) if description else "",
            asset=str(asset) if asset else "unknown",
            file_path=str(file_path) if file_path else None,
            line_number=line_number,
            cve_id=str(cve) if cve else None,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            recommendation=str(recommendation) if recommendation else "",
            raw_data=dict(row),
        )
    
    def _get_field(self, row: dict, headers: dict, keys: List[str]) -> Optional[str]:
        for key in keys:
            if key in headers:
                original_header = headers[key]
                value = row.get(original_header)
                if value:
                    return value
        return None
