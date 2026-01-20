import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class GCPSecurityCommandCenterParser(BaseParser):
    name = "gcp-scc"
    display_name = "Google Cloud Security Command Center"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "Google Cloud security findings"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "finding" in data[0] or "resourceName" in data[0]
            return "listFindingsResults" in data or "finding" in data
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if isinstance(data, list):
            gcp_findings = data
        elif "listFindingsResults" in data:
            gcp_findings = data["listFindingsResults"]
        else:
            gcp_findings = [data]
        
        for result in gcp_findings:
            finding_data = result.get("finding", result)
            
            severity_str = finding_data.get("severity", "MEDIUM")
            
            finding = ParsedFinding(
                title=finding_data.get("category", finding_data.get("findingClass", "GCP Security Finding")),
                severity=Severity.normalize(severity_str),
                tool="gcp-scc",
                description=finding_data.get("description", ""),
                asset=finding_data.get("resourceName", result.get("resource", {}).get("name", "unknown")),
                recommendation=finding_data.get("nextSteps", ""),
                references=[finding_data.get("externalUri")] if finding_data.get("externalUri") else [],
                tags=["gcp", finding_data.get("findingClass", ""), finding_data.get("category", "")],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
