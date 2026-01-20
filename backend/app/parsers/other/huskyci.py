import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class HuskyCIParser(BaseParser):
    name = "huskyci"
    display_name = "HuskyCI"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "HuskyCI security pipeline orchestrator"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "huskyciresults" in data or "goResults" in data or "npmResults" in data or "pythonResults" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("huskyciresults", data)
            for tool_key in ["goResults", "npmResults", "pythonResults", "javaResults", "rubyResults"]:
                tool_results = results.get(tool_key, {})
                for sev_level in ["highVulns", "mediumVulns", "lowVulns"]:
                    vulns = tool_results.get(sev_level, [])
                    for vuln in vulns:
                        findings.append(ParsedFinding(
                            title=vuln.get("title", vuln.get("details", "HuskyCI Finding")),
                            description=vuln.get("details", ""),
                            severity=self._map_level(sev_level),
                            tool=self.name,
                            asset=vuln.get("file", vuln.get("code", "unknown")),
                            raw_data=vuln
                        ))
        except:
            pass
        return findings

    def _map_level(self, level: str) -> str:
        mapping = {"highVulns": "high", "mediumVulns": "medium", "lowVulns": "low"}
        return mapping.get(level, "medium")
