import json
import csv
from io import StringIO
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AzureSecurityCenterParser(BaseParser):
    name = "azure-security-center"
    display_name = "Azure Security Center / Defender"
    category = ScannerCategory.CLOUD
    file_types = ["json", "csv"]
    description = "Microsoft Azure security recommendations"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                if isinstance(data, list) and len(data) > 0:
                    return "resourceGroup" in data[0] or "subscriptionId" in data[0]
                return "value" in data and "recommendations" in str(data).lower()[:500]
            return "subscriptionId" in content[:500] or "resourceGroup" in content[:500]
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if content.strip().startswith("{") or content.strip().startswith("["):
            return self._parse_json(content)
        else:
            return self._parse_csv(content)
    
    def _parse_json(self, content: str) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        if isinstance(data, dict):
            recommendations = data.get("value", [data])
        else:
            recommendations = data
        
        for rec in recommendations:
            severity_str = rec.get("severity", rec.get("properties", {}).get("severity", "Medium"))
            severity_map = {
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
            }
            
            finding = ParsedFinding(
                title=rec.get("displayName", rec.get("properties", {}).get("displayName", "Azure Recommendation")),
                severity=severity_map.get(severity_str, Severity.MEDIUM),
                tool="azure-security-center",
                description=rec.get("description", rec.get("properties", {}).get("description", "")),
                asset=rec.get("resourceId", rec.get("id", "unknown")),
                recommendation=rec.get("remediation", rec.get("properties", {}).get("remediationDescription", "")),
                tags=["azure", rec.get("category", "")],
                raw_data=rec,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(StringIO(content))
        
        for row in reader:
            finding = ParsedFinding(
                title=row.get("recommendationDisplayName", row.get("displayName", "Azure Recommendation")),
                severity=Severity.normalize(row.get("severity", "Medium")),
                tool="azure-security-center",
                description=row.get("description", ""),
                asset=row.get("resourceId", row.get("resourceName", "unknown")),
                tags=["azure", row.get("category", "")],
                raw_data=dict(row),
            )
            findings.append(finding)
        
        return findings
