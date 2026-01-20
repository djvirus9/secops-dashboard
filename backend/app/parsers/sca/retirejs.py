import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class RetireJSParser(BaseParser):
    name = "retirejs"
    display_name = "Retire.js"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Retire.js for detecting vulnerable JavaScript libraries"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                return "file" in first or "results" in first or "component" in first and "vulnerabilities" in first
            return "data" in data and isinstance(data["data"], list)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            items = data.get("data", data) if isinstance(data, dict) else data
            for item in items:
                file_path = item.get("file", "unknown")
                results = item.get("results", [item])
                for result in results:
                    component = result.get("component", result.get("library", "unknown"))
                    version = result.get("version", "")
                    for vuln in result.get("vulnerabilities", []):
                        severity = vuln.get("severity", "medium")
                        identifiers = vuln.get("identifiers", {})
                        cve = None
                        for cv in identifiers.get("CVE", []):
                            cve = cv
                            break
                        findings.append(ParsedFinding(
                            title=f"Vulnerable {component}@{version}",
                            description=vuln.get("info", [vuln.get("summary", "")])[0] if vuln.get("info") else vuln.get("summary", ""),
                            severity=self._map_severity(severity),
                            tool=self.name,
                            asset=f"{component}@{version}" if version else component,
                            cve=cve,
                            raw_data={"file": file_path, "component": component, "version": version, **vuln}
                        ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "info"}
        return mapping.get(str(sev).lower(), "medium")
