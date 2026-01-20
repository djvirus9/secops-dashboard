import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ClairParser(BaseParser):
    name = "clair"
    display_name = "Clair"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "CoreOS container vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("image" in data or "manifest_hash" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        image = data.get("image", data.get("manifest_hash", "unknown"))
        
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("name", vuln.get("vulnerability", {}).get("name"))
            
            finding = ParsedFinding(
                title=f"{cve_id}: {vuln.get('featurename', vuln.get('package', 'unknown'))}",
                severity=Severity.normalize(vuln.get("severity", "Unknown")),
                tool="clair",
                description=vuln.get("description", ""),
                asset=image,
                cve_id=cve_id,
                recommendation=f"Fixed in: {vuln.get('fixedby', 'No fix available')}",
                references=[vuln.get("link")] if vuln.get("link") else [],
                tags=["container", vuln.get("featurename", "")],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
