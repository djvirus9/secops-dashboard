import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PipAuditParser(BaseParser):
    name = "pip-audit"
    display_name = "pip-audit"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Python package vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                return "name" in first and "vulns" in first
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for pkg in data:
            pkg_name = pkg.get("name", "unknown")
            version = pkg.get("version", "")
            
            for vuln in pkg.get("vulns", []):
                vuln_id = vuln.get("id", "")
                
                cve_id = None
                if vuln_id.startswith("CVE-"):
                    cve_id = vuln_id
                
                aliases = vuln.get("aliases", [])
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
                
                fix_versions = vuln.get("fix_versions", [])
                recommendation = ""
                if fix_versions:
                    recommendation = f"Upgrade {pkg_name} to version: {', '.join(fix_versions)}"
                
                finding = ParsedFinding(
                    title=f"{vuln_id}: {pkg_name} {version}",
                    severity=Severity.HIGH,
                    tool="pip-audit",
                    description=vuln.get("description", ""),
                    asset=f"{pkg_name}=={version}",
                    cve_id=cve_id,
                    recommendation=recommendation,
                    tags=["python", "pip", pkg_name],
                    raw_data=vuln,
                )
                findings.append(finding)
        
        return findings
