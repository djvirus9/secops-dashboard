import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class WebinspectParser(BaseParser):
    name = "webinspect"
    display_name = "Micro Focus WebInspect"
    category = ScannerCategory.DAST
    file_types = ["xml"]
    description = "Micro Focus WebInspect dynamic application security testing"

    def can_parse(self, content: str) -> bool:
        return "WebInspect" in content or "webinspect" in content.lower() or "Fortify WebInspect" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
            for issue in root.findall(".//Issue") or root.findall(".//issue") or root.findall(".//Vulnerability"):
                name = issue.findtext("Name") or issue.findtext("name") or issue.findtext("CheckType") or "WebInspect Finding"
                findings.append(ParsedFinding(
                    title=name,
                    description=issue.findtext("Description") or issue.findtext("description") or "",
                    severity=self._map_severity(issue.findtext("Severity") or issue.findtext("severity") or "medium"),
                    tool=self.name,
                    asset=issue.findtext("URL") or issue.findtext("url") or issue.findtext("Host") or "unknown",
                    cwe=issue.findtext("CWE") or issue.findtext("cwe"),
                    raw_data={"xml": True}
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        try:
            level = int(sev)
            if level >= 4: return "critical"
            if level >= 3: return "high"
            if level >= 2: return "medium"
            return "low"
        except:
            mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "best practice": "info"}
            return mapping.get(str(sev).lower(), "medium")
