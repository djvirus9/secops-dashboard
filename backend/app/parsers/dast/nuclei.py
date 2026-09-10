import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def load_nuclei_records(content: str) -> list:
    try:
        document = json.loads(content)
        return document if isinstance(document, list) else [document]
    except json.JSONDecodeError:
        return [json.loads(line) for line in content.splitlines() if line.strip()]


@ParserRegistry.register
class NucleiParser(BaseParser):
    name = "nuclei"
    display_name = "Nuclei"
    category = ScannerCategory.DAST
    file_types = ["json", "jsonl"]
    description = "ProjectDiscovery fast vulnerability scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            records = load_nuclei_records(content)
            return bool(records) and all(
                isinstance(data, dict) and any(key in data for key in ("template-id", "templateID", "template"))
                for data in records[:5]
            )
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        
        for result in load_nuclei_records(content):
            template_id = result.get("template-id") or result.get("templateID") or result.get("template", "unknown")
            info = result.get("info", {})
            
            severity_str = info.get("severity", result.get("severity", "info"))
            
            cve_id = None
            cve_list = info.get("classification", {}).get("cve-id") or info.get("cve")
            if cve_list:
                if isinstance(cve_list, list) and cve_list:
                    cve_id = cve_list[0]
                elif isinstance(cve_list, str):
                    cve_id = cve_list
            
            cwe_id = None
            cwe_list = info.get("classification", {}).get("cwe-id")
            if cwe_list:
                if isinstance(cwe_list, list) and cwe_list:
                    try:
                        cwe_id = int(str(cwe_list[0]).replace("CWE-", ""))
                    except:
                        pass
            
            cvss_score = None
            cvss = info.get("classification", {}).get("cvss-score")
            if cvss:
                try:
                    cvss_score = float(cvss)
                except:
                    pass
            
            host = result.get("host", result.get("matched-at", result.get("url", "unknown")))
            
            finding = ParsedFinding(
                title=info.get("name", template_id),
                severity=Severity.normalize(severity_str),
                tool="nuclei",
                source_id=template_id,
                component=result.get("matched-at", result.get("url")),
                description=info.get("description", ""),
                asset=host,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                recommendation=info.get("remediation", ""),
                references=info.get("reference", []) if isinstance(info.get("reference"), list) else [info.get("reference")] if info.get("reference") else [],
                tags=info.get("tags", []) if isinstance(info.get("tags"), list) else info.get("tags", "").split(",") if info.get("tags") else [],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
