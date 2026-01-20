import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AnchoreParser(BaseParser):
    name = "anchore"
    display_name = "Anchore Engine"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Anchore container security analysis"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("imageDigest" in data or "image" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        image = data.get("imageDigest", data.get("image", {}).get("imageDigest", "unknown"))
        
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("vuln", vuln.get("cve"))
            
            cvss_v3 = vuln.get("nvd_data", [{}])[0].get("cvss_v3", {}).get("base_score") if vuln.get("nvd_data") else None
            
            finding = ParsedFinding(
                title=f"{cve_id}: {vuln.get('package', 'unknown')}",
                severity=Severity.normalize(vuln.get("severity", "Unknown")),
                tool="anchore",
                description=vuln.get("description", ""),
                asset=image,
                cve_id=cve_id,
                cvss_score=cvss_v3,
                recommendation=f"Fix available: {vuln.get('fix', 'None')}" if vuln.get("fix") else "",
                references=[vuln.get("url")] if vuln.get("url") else [],
                tags=["container", vuln.get("package_type", ""), vuln.get("package", "")],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
