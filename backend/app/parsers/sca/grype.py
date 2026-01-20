import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GrypeParser(BaseParser):
    name = "grype"
    display_name = "Grype"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Anchore container and filesystem vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "matches" in data and "source" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        source = data.get("source", {})
        source_target = source.get("target", {})
        if isinstance(source_target, dict):
            asset_name = source_target.get("userInput", source_target.get("imageID", "unknown"))
        else:
            asset_name = str(source_target)
        
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            
            cve_id = vuln.get("id")
            
            cvss_data = vuln.get("cvss", [])
            cvss_score = None
            for cvss in cvss_data:
                if cvss.get("version", "").startswith("3"):
                    score = cvss.get("metrics", {}).get("baseScore")
                    if score:
                        cvss_score = float(score)
                        break
            
            pkg_name = artifact.get("name", "")
            version = artifact.get("version", "")
            fixed_versions = vuln.get("fix", {}).get("versions", [])
            
            recommendation = ""
            if fixed_versions:
                recommendation = f"Upgrade {pkg_name} to: {', '.join(fixed_versions)}"
            
            finding = ParsedFinding(
                title=f"{cve_id}: {pkg_name} {version}",
                severity=Severity.normalize(vuln.get("severity", "Unknown")),
                tool="grype",
                description=vuln.get("description", ""),
                asset=asset_name,
                cve_id=cve_id,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=vuln.get("urls", []),
                tags=[artifact.get("type", ""), pkg_name],
                raw_data=match,
            )
            findings.append(finding)
        
        return findings
