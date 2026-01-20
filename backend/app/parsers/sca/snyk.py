import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SnykParser(BaseParser):
    name = "snyk"
    display_name = "Snyk"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Developer security platform for code, dependencies, containers, and IaC"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("projectName" in data or "path" in data or "displayTargetFile" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        project = data.get("projectName", data.get("path", "unknown"))
        
        for vuln in data.get("vulnerabilities", []):
            cve_ids = vuln.get("identifiers", {}).get("CVE", [])
            cve_id = cve_ids[0] if cve_ids else None
            
            cwe_ids = vuln.get("identifiers", {}).get("CWE", [])
            cwe_id = None
            if cwe_ids:
                try:
                    cwe_id = int(str(cwe_ids[0]).replace("CWE-", ""))
                except:
                    pass
            
            cvss_score = vuln.get("cvssScore")
            
            pkg_name = vuln.get("packageName", vuln.get("name", ""))
            version = vuln.get("version", "")
            
            upgrade_path = vuln.get("upgradePath", [])
            fixed_in = vuln.get("fixedIn", [])
            recommendation = ""
            if fixed_in:
                recommendation = f"Upgrade to version: {', '.join(fixed_in)}"
            elif upgrade_path:
                recommendation = f"Upgrade path: {' → '.join(str(p) for p in upgrade_path if p)}"
            
            finding = ParsedFinding(
                title=vuln.get("title", f"{cve_id or vuln.get('id', 'Vulnerability')}: {pkg_name}"),
                severity=Severity.normalize(vuln.get("severity", "medium")),
                tool="snyk",
                description=vuln.get("description", ""),
                asset=project,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=vuln.get("references", []),
                tags=[pkg_name, version] if version else [pkg_name],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
