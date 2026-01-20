import json
import csv
import io
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class ContrastParser(BaseParser):
    name = "contrast"
    display_name = "Contrast Security"
    category = ScannerCategory.SAST
    file_types = ["json", "csv"]
    description = "Contrast Security IAST/RASP findings"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return "traces" in data or "vulnerabilities" in data or "contrast" in str(data).lower()
            return False
        except:
            return "Vulnerability Name" in content and "Severity" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                traces = data.get("traces", data.get("vulnerabilities", []))
                if isinstance(data, list):
                    traces = data
                for trace in traces:
                    findings.append(ParsedFinding(
                        title=trace.get("title", trace.get("rule_name", "Contrast Finding")),
                        description=trace.get("story", trace.get("description", "")),
                        severity=self._map_severity(trace.get("severity", "medium")),
                        tool=self.name,
                        asset=trace.get("application", {}).get("name", trace.get("app_name", "unknown")),
                        cwe=trace.get("cwe"),
                        raw_data=trace
                    ))
            else:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    findings.append(ParsedFinding(
                        title=row.get("Vulnerability Name", row.get("title", "Contrast Finding")),
                        description=row.get("Description", ""),
                        severity=self._map_severity(row.get("Severity", "medium")),
                        tool=self.name,
                        asset=row.get("Application", "unknown"),
                        raw_data=dict(row)
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "note": "info"}
        return mapping.get(str(sev).lower(), "medium")
