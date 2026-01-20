import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TrivyParser(BaseParser):
    name = "trivy"
    display_name = "Trivy"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Aqua Security comprehensive vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "Results" in data or ("SchemaVersion" in data and "ArtifactName" in data)
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        artifact_name = data.get("ArtifactName", "unknown")
        
        for result in data.get("Results", []):
            target = result.get("Target", artifact_name)
            result_type = result.get("Type", "")
            
            for vuln in result.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID")
                
                cvss_score = None
                cvss_data = vuln.get("CVSS", {})
                for source in ["nvd", "redhat", "ghsa"]:
                    if source in cvss_data:
                        cvss_score = cvss_data[source].get("V3Score") or cvss_data[source].get("V2Score")
                        if cvss_score:
                            break
                
                cwe_ids = vuln.get("CweIDs", [])
                cwe_id = None
                if cwe_ids:
                    try:
                        cwe_id = int(cwe_ids[0].replace("CWE-", ""))
                    except:
                        pass
                
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                
                title = f"{cve_id or vuln.get('Title', 'Vulnerability')}: {pkg_name}"
                
                finding = ParsedFinding(
                    title=title,
                    severity=Severity.normalize(vuln.get("Severity", "UNKNOWN")),
                    tool="trivy",
                    description=vuln.get("Description", ""),
                    asset=target,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    cvss_score=cvss_score,
                    recommendation=f"Upgrade {pkg_name} from {installed} to {fixed}" if fixed else "",
                    references=vuln.get("References", []),
                    tags=[result_type, pkg_name] if result_type else [pkg_name],
                    raw_data=vuln,
                )
                findings.append(finding)
            
            for misconfig in result.get("Misconfigurations", []):
                finding = ParsedFinding(
                    title=misconfig.get("Title", misconfig.get("ID", "Misconfiguration")),
                    severity=Severity.normalize(misconfig.get("Severity", "MEDIUM")),
                    tool="trivy",
                    description=misconfig.get("Description", ""),
                    asset=target,
                    recommendation=misconfig.get("Resolution", ""),
                    references=misconfig.get("References", []),
                    tags=["misconfiguration", misconfig.get("Type", "")],
                    raw_data=misconfig,
                )
                findings.append(finding)
            
            for secret in result.get("Secrets", []):
                finding = ParsedFinding(
                    title=f"Secret Detected: {secret.get('RuleID', secret.get('Category', 'Unknown'))}",
                    severity=Severity.HIGH,
                    tool="trivy",
                    description=secret.get("Title", ""),
                    asset=target,
                    file_path=target,
                    line_number=secret.get("StartLine"),
                    tags=["secrets", secret.get("Category", "")],
                    raw_data=secret,
                )
                findings.append(finding)
        
        return findings
