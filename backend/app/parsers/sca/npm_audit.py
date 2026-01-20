import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class NpmAuditParser(BaseParser):
    name = "npm-audit"
    display_name = "npm audit"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Node.js npm package vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return ("advisories" in data or "vulnerabilities" in data) and ("metadata" in data or "auditReportVersion" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if "vulnerabilities" in data:
            return self._parse_v2(data)
        else:
            return self._parse_v1(data)
    
    def _parse_v2(self, data: dict) -> List[ParsedFinding]:
        findings = []
        
        for pkg_name, vuln_data in data.get("vulnerabilities", {}).items():
            severity_str = vuln_data.get("severity", "moderate")
            
            for via in vuln_data.get("via", []):
                if isinstance(via, dict):
                    cve_id = None
                    cwe_ids = via.get("cwe", [])
                    cwe_id = None
                    if cwe_ids:
                        try:
                            cwe_id = int(str(cwe_ids[0]).replace("CWE-", ""))
                        except:
                            pass
                    
                    finding = ParsedFinding(
                        title=via.get("title", f"Vulnerability in {pkg_name}"),
                        severity=Severity.normalize(via.get("severity", severity_str)),
                        tool="npm-audit",
                        description=via.get("title", ""),
                        asset=pkg_name,
                        cwe_id=cwe_id,
                        recommendation=f"Fix available: {vuln_data.get('fixAvailable', 'Check npm audit fix')}",
                        references=[via.get("url")] if via.get("url") else [],
                        tags=["npm", pkg_name, vuln_data.get("range", "")],
                        raw_data=via,
                    )
                    findings.append(finding)
        
        return findings
    
    def _parse_v1(self, data: dict) -> List[ParsedFinding]:
        findings = []
        
        for advisory_id, advisory in data.get("advisories", {}).items():
            cwe_id = None
            if advisory.get("cwe"):
                try:
                    cwe_id = int(str(advisory["cwe"]).replace("CWE-", ""))
                except:
                    pass
            
            finding = ParsedFinding(
                title=advisory.get("title", f"Advisory {advisory_id}"),
                severity=Severity.normalize(advisory.get("severity", "moderate")),
                tool="npm-audit",
                description=advisory.get("overview", ""),
                asset=advisory.get("module_name", "unknown"),
                cwe_id=cwe_id,
                recommendation=advisory.get("recommendation", ""),
                references=[advisory.get("url")] if advisory.get("url") else [],
                tags=["npm", advisory.get("module_name", "")],
                raw_data=advisory,
            )
            findings.append(finding)
        
        return findings
