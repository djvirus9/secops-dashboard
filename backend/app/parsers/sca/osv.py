import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class OSVParser(BaseParser):
    name = "osv-scanner"
    display_name = "OSV Scanner"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Google Open Source Vulnerabilities scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and isinstance(data["results"], list)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for result in data.get("results", []):
            source = result.get("source", {})
            source_path = source.get("path", "unknown")
            
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                pkg_name = pkg_info.get("name", "unknown")
                version = pkg_info.get("version", "")
                
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "")
                    
                    cve_id = None
                    aliases = vuln.get("aliases", [])
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break
                    if not cve_id and vuln_id.startswith("CVE-"):
                        cve_id = vuln_id
                    
                    severity_data = vuln.get("database_specific", {}).get("severity")
                    severity_str = severity_data if severity_data else "MEDIUM"
                    
                    affected = vuln.get("affected", [{}])[0] if vuln.get("affected") else {}
                    ranges = affected.get("ranges", [])
                    fixed_version = None
                    for r in ranges:
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                break
                    
                    recommendation = ""
                    if fixed_version:
                        recommendation = f"Upgrade {pkg_name} to version {fixed_version}"
                    
                    finding = ParsedFinding(
                        title=f"{vuln_id}: {pkg_name}",
                        severity=Severity.normalize(severity_str),
                        tool="osv-scanner",
                        description=vuln.get("summary", vuln.get("details", "")),
                        asset=source_path,
                        cve_id=cve_id,
                        recommendation=recommendation,
                        references=[ref.get("url") for ref in vuln.get("references", []) if ref.get("url")],
                        tags=["osv", pkg_name, pkg_info.get("ecosystem", "")],
                        raw_data=vuln,
                    )
                    findings.append(finding)
        
        return findings
