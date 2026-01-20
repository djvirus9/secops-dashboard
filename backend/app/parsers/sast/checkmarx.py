import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CheckmarxParser(BaseParser):
    name = "checkmarx"
    display_name = "Checkmarx"
    category = ScannerCategory.SAST
    file_types = ["json", "xml", "csv"]
    description = "Enterprise SAST solution for secure code review"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return "scanId" in data or "CxXMLResults" in content or "checkmarx" in str(data).lower()
            return False
        except:
            return "CxXMLResults" in content or "Checkmarx" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("results", data.get("vulnerabilities", []))
            if isinstance(data, dict) and not results:
                results = [data]
            for item in results:
                findings.append(ParsedFinding(
                    title=item.get("queryName", item.get("name", "Checkmarx Finding")),
                    description=item.get("description", item.get("resultDescription", "")),
                    severity=self._map_severity(item.get("severity", "medium")),
                    tool=self.name,
                    asset=item.get("sourceFile", item.get("file", "unknown")),
                    cwe=item.get("cweId"),
                    raw_data=item
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "info": "info", "information": "info"}
        return mapping.get(str(sev).lower(), "medium")
