import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class DependencyCheckParser(BaseParser):
    name = "dependency-check"
    display_name = "OWASP Dependency-Check"
    category = ScannerCategory.SCA
    file_types = ["json", "xml"]
    description = "OWASP software composition analysis tool"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "dependencies" in data and "scanInfo" in data
            elif content.strip().startswith("<"):
                return "dependency-check" in content.lower()[:500]
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if content.strip().startswith("{"):
            return self._parse_json(content)
        else:
            return self._parse_xml(content)
    
    def _parse_json(self, content: str) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for dep in data.get("dependencies", []):
            file_path = dep.get("filePath", dep.get("fileName", "unknown"))
            
            for vuln in dep.get("vulnerabilities", []):
                cve_id = vuln.get("name")
                
                cvss_score = None
                if vuln.get("cvssv3"):
                    cvss_score = vuln["cvssv3"].get("baseScore")
                elif vuln.get("cvssv2"):
                    cvss_score = vuln["cvssv2"].get("score")
                
                severity_str = vuln.get("severity", "MEDIUM")
                
                cwe_ids = vuln.get("cwes", [])
                cwe_id = None
                if cwe_ids:
                    try:
                        cwe_id = int(str(cwe_ids[0]).replace("CWE-", ""))
                    except:
                        pass
                
                finding = ParsedFinding(
                    title=f"{cve_id}: {dep.get('fileName', 'Unknown Package')}",
                    severity=Severity.normalize(severity_str),
                    tool="dependency-check",
                    description=vuln.get("description", ""),
                    asset=file_path,
                    file_path=file_path,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    cvss_score=cvss_score,
                    references=vuln.get("references", []),
                    tags=["dependency", dep.get("fileName", "")],
                    raw_data=vuln,
                )
                findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        ns = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd"}
        findings = []
        
        for dep in root.findall(".//dc:dependency", ns) or root.findall(".//dependency"):
            file_path = dep.findtext("dc:filePath", dep.findtext("filePath", "unknown"), ns)
            file_name = dep.findtext("dc:fileName", dep.findtext("fileName", "unknown"), ns)
            
            vulns = dep.findall(".//dc:vulnerability", ns) or dep.findall(".//vulnerability")
            for vuln in vulns:
                cve_id = vuln.findtext("dc:name", vuln.findtext("name", ""), ns)
                severity_str = vuln.findtext("dc:severity", vuln.findtext("severity", "MEDIUM"), ns)
                
                finding = ParsedFinding(
                    title=f"{cve_id}: {file_name}",
                    severity=Severity.normalize(severity_str),
                    tool="dependency-check",
                    description=vuln.findtext("dc:description", vuln.findtext("description", ""), ns),
                    asset=file_path,
                    file_path=file_path,
                    cve_id=cve_id,
                    tags=["dependency", file_name],
                    raw_data={},
                )
                findings.append(finding)
        
        return findings
