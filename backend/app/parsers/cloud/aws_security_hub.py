import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AWSSecurityHubParser(BaseParser):
    name = "aws-security-hub"
    display_name = "AWS Security Hub"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "AWS Security Hub findings (ASFF format)"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                findings = data.get("Findings", [data])
            else:
                findings = data
            
            if len(findings) > 0:
                first = findings[0]
                return "AwsAccountId" in first or "ProductArn" in first or "SchemaVersion" in first
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if isinstance(data, dict):
            aws_findings = data.get("Findings", [data])
        else:
            aws_findings = data
        
        for asff in aws_findings:
            severity_label = asff.get("Severity", {}).get("Label", "INFORMATIONAL")
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFORMATIONAL": Severity.INFO,
            }
            
            resources = asff.get("Resources", [])
            asset = resources[0].get("Id", "unknown") if resources else "unknown"
            
            finding = ParsedFinding(
                title=asff.get("Title", "AWS Security Hub Finding"),
                severity=severity_map.get(severity_label, Severity.INFO),
                tool="aws-security-hub",
                description=asff.get("Description", ""),
                asset=asset,
                recommendation=asff.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                references=[asff.get("Remediation", {}).get("Recommendation", {}).get("Url", "")] if asff.get("Remediation") else [],
                tags=["aws", asff.get("ProductFields", {}).get("ControlId", ""), asff.get("GeneratorId", "")],
                raw_data=asff,
            )
            findings.append(finding)
        
        return findings
