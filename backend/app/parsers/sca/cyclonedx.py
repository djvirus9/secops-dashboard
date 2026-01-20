import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CycloneDXParser(BaseParser):
    name = "cyclonedx"
    display_name = "CycloneDX"
    category = ScannerCategory.SCA
    file_types = ["json", "xml"]
    description = "OWASP CycloneDX Software Bill of Materials"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "bomFormat" in data and data["bomFormat"] == "CycloneDX"
            elif content.strip().startswith("<"):
                return "cyclonedx" in content.lower()[:500]
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
        
        for vuln in data.get("vulnerabilities", []):
            vuln_id = vuln.get("id", "unknown")
            
            cve_id = None
            if vuln_id.startswith("CVE-"):
                cve_id = vuln_id
            
            cwe_ids = vuln.get("cwes", [])
            cwe_id = None
            if cwe_ids:
                try:
                    cwe_id = int(cwe_ids[0])
                except:
                    pass
            
            ratings = vuln.get("ratings", [])
            severity_str = "medium"
            cvss_score = None
            for rating in ratings:
                if rating.get("severity"):
                    severity_str = rating["severity"]
                if rating.get("score"):
                    cvss_score = float(rating["score"])
            
            affects = vuln.get("affects", [])
            affected_refs = [a.get("ref", "") for a in affects]
            
            finding = ParsedFinding(
                title=f"{vuln_id}: {vuln.get('description', 'Vulnerability')[:50]}",
                severity=Severity.normalize(severity_str),
                tool="cyclonedx",
                description=vuln.get("description", ""),
                asset=", ".join(affected_refs) if affected_refs else "unknown",
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                recommendation=vuln.get("recommendation", ""),
                references=[s.get("url") for s in vuln.get("source", {}).get("references", []) if s.get("url")],
                tags=["sbom", "cyclonedx"],
                raw_data=vuln,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        ns = {"cdx": "http://cyclonedx.org/schema/bom/1.4"}
        findings = []
        
        for vuln in root.findall(".//cdx:vulnerability", ns) or root.findall(".//vulnerability"):
            vuln_id = vuln.findtext("cdx:id", vuln.findtext("id", "unknown"), ns)
            
            cve_id = None
            if vuln_id.startswith("CVE-"):
                cve_id = vuln_id
            
            severity_str = "medium"
            for rating in vuln.findall(".//cdx:rating", ns) or vuln.findall(".//rating"):
                sev = rating.findtext("cdx:severity", rating.findtext("severity", ""), ns)
                if sev:
                    severity_str = sev
                    break
            
            finding = ParsedFinding(
                title=vuln_id,
                severity=Severity.normalize(severity_str),
                tool="cyclonedx",
                description=vuln.findtext("cdx:description", vuln.findtext("description", ""), ns),
                asset="unknown",
                cve_id=cve_id,
                tags=["sbom", "cyclonedx"],
                raw_data={},
            )
            findings.append(finding)
        
        return findings
