import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class HCLAppScanParser(BaseParser):
    name = "hcl_appscan"
    display_name = "HCL AppScan"
    category = ScannerCategory.DAST
    file_types = ["xml", "json"]
    description = "HCL AppScan dynamic application security testing"

    def can_parse(self, content: str) -> bool:
        return "AppScan" in content or "appscan" in content.lower() or "hcl" in content.lower() and "scan" in content.lower()

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for issue in root.findall(".//issue") or root.findall(".//Issue") or root.findall(".//item"):
                    name = issue.findtext("name") or issue.findtext("issue-type") or "HCL AppScan Finding"
                    findings.append(ParsedFinding(
                        title=name,
                        description=issue.findtext("description", issue.findtext("advisory", "")),
                        severity=self._map_severity(issue.findtext("severity", "medium")),
                        tool=self.name,
                        asset=issue.findtext("url", issue.findtext("affected-url", "unknown")),
                        cwe=issue.findtext("cwe"),
                        raw_data={"xml": True}
                    ))
            else:
                data = json.loads(content)
                issues = data.get("issues", data.get("findings", []))
                for issue in issues:
                    findings.append(ParsedFinding(
                        title=issue.get("name", issue.get("issueType", "HCL AppScan Finding")),
                        description=issue.get("description", issue.get("advisory", "")),
                        severity=self._map_severity(issue.get("severity", "medium")),
                        tool=self.name,
                        asset=issue.get("url", issue.get("affectedUrl", "unknown")),
                        cwe=issue.get("cwe"),
                        raw_data=issue
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return mapping.get(str(sev).lower(), "medium")
