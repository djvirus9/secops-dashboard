import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class IBMAppScanParser(BaseParser):
    name = "ibm_appscan"
    display_name = "IBM AppScan"
    category = ScannerCategory.DAST
    file_types = ["xml"]
    description = "IBM Security AppScan vulnerability scanner"

    def can_parse(self, content: str) -> bool:
        return "AppScan" in content and ("IBM" in content or "xml-report" in content or "issues" in content.lower())

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
            for issue in root.findall(".//issue") or root.findall(".//Issue") or root.findall(".//item"):
                issue_type = issue.find("issue-type") or issue.find("name") or issue.find("IssueType")
                name = issue_type.text if issue_type is not None else "IBM AppScan Finding"
                desc_el = issue.find("advisory") or issue.find("description")
                desc = desc_el.text if desc_el is not None else ""
                sev_el = issue.find("severity") or issue.find("Severity")
                sev = sev_el.text if sev_el is not None else "medium"
                url_el = issue.find("url") or issue.find("Url")
                url = url_el.text if url_el is not None else "unknown"
                cwe_el = issue.find("cwe")
                cwe = cwe_el.text if cwe_el is not None else None
                findings.append(ParsedFinding(
                    title=name,
                    description=desc,
                    severity=self._map_severity(sev),
                    tool=self.name,
                    asset=url,
                    cwe=cwe,
                    raw_data={"xml": True}
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return mapping.get(str(sev).lower(), "medium")
