import json
from typing import List, Optional, Dict, Any

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GenericJSONParser(BaseParser):
    name = "generic-json"
    display_name = "Generic JSON"
    category = ScannerCategory.GENERIC
    file_types = ["json"]
    description = "Generic JSON findings import"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        items = self._extract_findings_array(data)
        
        for item in items:
            finding = self._parse_item(item)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _extract_findings_array(self, data: Any) -> List[Dict]:
        if isinstance(data, list):
            return data
        
        if isinstance(data, dict):
            for key in ["findings", "vulnerabilities", "issues", "results", "alerts", "items", "data"]:
                if key in data and isinstance(data[key], list):
                    return data[key]
            
            return [data]
        
        return []
    
    def _parse_item(self, item: Dict) -> Optional[ParsedFinding]:
        if not isinstance(item, dict):
            return None
        
        title = self._extract_field(item, ["title", "name", "summary", "message", "description", "rule_id", "id"])
        if not title:
            return None
        
        severity_str = self._extract_field(item, ["severity", "level", "risk", "priority", "criticality"])
        
        description = self._extract_field(item, ["description", "message", "details", "body", "content"])
        
        asset = self._extract_field(item, ["asset", "host", "target", "url", "file", "path", "resource", "component"])
        
        file_path = self._extract_field(item, ["file", "file_path", "filepath", "path", "filename", "location"])
        
        line = self._extract_field(item, ["line", "line_number", "lineNumber", "start_line"])
        line_number = int(line) if line and str(line).isdigit() else None
        
        cve = self._extract_field(item, ["cve", "cve_id", "cveId", "vulnerability_id"])
        
        cwe = self._extract_field(item, ["cwe", "cwe_id", "cweId"])
        cwe_id = None
        if cwe:
            try:
                cwe_id = int(str(cwe).replace("CWE-", ""))
            except:
                pass
        
        cvss = self._extract_field(item, ["cvss", "cvss_score", "cvssScore", "score"])
        cvss_score = None
        if cvss:
            try:
                cvss_score = float(cvss)
            except:
                pass
        
        recommendation = self._extract_field(item, ["recommendation", "remediation", "fix", "solution", "mitigation"])
        
        refs = item.get("references", item.get("links", item.get("urls", [])))
        if isinstance(refs, str):
            refs = [refs]
        elif not isinstance(refs, list):
            refs = []
        
        return ParsedFinding(
            title=str(title)[:200],
            severity=Severity.normalize(severity_str) if severity_str else Severity.MEDIUM,
            tool="generic-json",
            description=str(description) if description else "",
            asset=str(asset) if asset else "unknown",
            file_path=str(file_path) if file_path else None,
            line_number=line_number,
            cve_id=str(cve) if cve else None,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            recommendation=str(recommendation) if recommendation else "",
            references=refs,
            raw_data=item,
        )
    
    def _extract_field(self, item: Dict, keys: List[str]) -> Optional[Any]:
        for key in keys:
            if key in item and item[key] is not None:
                return item[key]
            
            lower_key = key.lower()
            for k, v in item.items():
                if k.lower() == lower_key and v is not None:
                    return v
        return None
