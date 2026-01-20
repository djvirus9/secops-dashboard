import json
import csv
from io import StringIO
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ProwlerParser(BaseParser):
    name = "prowler"
    display_name = "Prowler"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json", "csv"]
    description = "AWS/Azure/GCP security assessment tool"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                if isinstance(data, list) and len(data) > 0:
                    return "CheckID" in data[0] or "check_id" in data[0] or "StatusExtended" in data[0]
            return "CHECK_ID" in content[:500] or "SEVERITY" in content[:500]
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
            data = [data]
        
        for result in data:
            status = result.get("Status", result.get("status", ""))
            if status.upper() == "PASS":
                continue
            
            check_id = result.get("CheckID", result.get("check_id", ""))
            
            finding = ParsedFinding(
                title=result.get("CheckTitle", result.get("check_title", check_id)),
                severity=Severity.normalize(result.get("Severity", result.get("severity", "medium"))),
                tool="prowler",
                description=result.get("StatusExtended", result.get("status_extended", "")),
                asset=result.get("ResourceId", result.get("resource_id", result.get("ResourceArn", "unknown"))),
                recommendation=result.get("Remediation", {}).get("Recommendation", {}).get("Text", "") if isinstance(result.get("Remediation"), dict) else "",
                references=result.get("Remediation", {}).get("Recommendation", {}).get("Url", []) if isinstance(result.get("Remediation"), dict) else [],
                tags=[result.get("Provider", ""), result.get("ServiceName", result.get("service_name", "")), check_id],
                raw_data=result,
            )
            findings.append(finding)
        
        return findings
    
    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(StringIO(content))
        
        for row in reader:
            status = row.get("STATUS", row.get("Status", ""))
            if status.upper() == "PASS":
                continue
            
            finding = ParsedFinding(
                title=row.get("CHECK_TITLE", row.get("CheckTitle", row.get("CHECK_ID", "Unknown"))),
                severity=Severity.normalize(row.get("SEVERITY", row.get("Severity", "medium"))),
                tool="prowler",
                description=row.get("STATUS_EXTENDED", row.get("StatusExtended", "")),
                asset=row.get("RESOURCE_ID", row.get("ResourceId", "unknown")),
                tags=["prowler", row.get("PROVIDER", ""), row.get("SERVICE_NAME", "")],
                raw_data=dict(row),
            )
            findings.append(finding)
        
        return findings
