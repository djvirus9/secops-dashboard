import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class ORTParser(BaseParser):
    name = "ort"
    display_name = "OSS Review Toolkit (ORT)"
    category = ScannerCategory.OTHER
    file_types = ["json", "xml"]
    description = "OSS Review Toolkit for license compliance and vulnerability scanning"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "analyzer" in data or "advisor" in data or "scanner" in data or "repository" in data and "config" in data
        except:
            return "ort-result" in content.lower()

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            advisor = data.get("advisor", {})
            results = advisor.get("results", {})
            for pkg_id, advisories in results.items():
                if isinstance(advisories, dict):
                    for advisory in advisories.get("advisories", []):
                        for vuln in advisory.get("vulnerabilities", []):
                            findings.append(ParsedFinding(
                                title=vuln.get("id", vuln.get("externalId", "ORT Vulnerability")),
                                description=vuln.get("summary", vuln.get("description", "")),
                                severity=self._map_severity(vuln.get("severity", "medium")),
                                tool=self.name,
                                asset=pkg_id,
                                cve=vuln.get("id") if str(vuln.get("id", "")).startswith("CVE") else None,
                                raw_data=vuln
                            ))
            evaluator = data.get("evaluator", {})
            for violation in evaluator.get("violations", []):
                findings.append(ParsedFinding(
                    title=violation.get("rule", violation.get("message", "ORT Violation")),
                    description=violation.get("message", ""),
                    severity=self._map_severity(violation.get("severity", "medium")),
                    tool=self.name,
                    asset=violation.get("pkg", "unknown"),
                    raw_data=violation
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "warning": "medium", "error": "high", "hint": "info"}
        return mapping.get(str(sev).lower(), "medium")
