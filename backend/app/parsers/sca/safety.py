import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SafetyParser(BaseParser):
    name = "safety"
    display_name = "Safety"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Python dependency security checker"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                return len(first) >= 4 and isinstance(first[0], str)
            if isinstance(data, dict):
                return "report" in data or "vulnerabilities" in data
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if isinstance(data, list):
            return self._parse_list(data)
        else:
            return self._parse_report(data)
    
    def _parse_list(self, data: list) -> List[ParsedFinding]:
        findings = []
        
        for item in data:
            if len(item) >= 4:
                pkg_name = item[0]
                affected_versions = item[1]
                installed_version = item[2]
                description = item[3]
                vuln_id = item[4] if len(item) > 4 else ""
                
                finding = ParsedFinding(
                    title=f"{vuln_id or 'Vulnerability'}: {pkg_name}",
                    severity=Severity.HIGH,
                    tool="safety",
                    description=description,
                    asset=f"{pkg_name}=={installed_version}",
                    recommendation=f"Affected versions: {affected_versions}",
                    tags=["python", pkg_name],
                    raw_data={"item": item},
                )
                findings.append(finding)
        
        return findings
    
    def _parse_report(self, data: dict) -> List[ParsedFinding]:
        findings = []
        
        vulns = data.get("vulnerabilities", data.get("report", {}).get("vulnerabilities", []))
        
        for vuln in vulns:
            cve_id = vuln.get("CVE")
            
            finding = ParsedFinding(
                title=vuln.get("vulnerability_id", f"Vulnerability in {vuln.get('package_name', 'unknown')}"),
                severity=Severity.normalize(vuln.get("severity", "high")),
                tool="safety",
                description=vuln.get("advisory", ""),
                asset=f"{vuln.get('package_name', 'unknown')}=={vuln.get('analyzed_version', '')}",
                cve_id=cve_id,
                recommendation=vuln.get("recommendation", ""),
                tags=["python", vuln.get("package_name", "")],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
