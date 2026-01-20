import json
import csv
import io
import zipfile
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class BlackDuckParser(BaseParser):
    name = "blackduck"
    display_name = "Black Duck"
    category = ScannerCategory.SCA
    file_types = ["json", "csv", "zip"]
    description = "Synopsys Black Duck software composition analysis"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "items" in data and "totalCount" in data or "blackduck" in str(data).lower() or "componentVersion" in str(data)
        except:
            return "Component Name" in content or "Vulnerability ID" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                items = data.get("items", data if isinstance(data, list) else [])
                for item in items:
                    vuln = item.get("vulnerabilityWithRemediation", item)
                    comp = item.get("component", {})
                    findings.append(ParsedFinding(
                        title=vuln.get("vulnerabilityName", vuln.get("name", "Black Duck Vulnerability")),
                        description=vuln.get("description", ""),
                        severity=self._map_severity(vuln.get("severity", vuln.get("overallScore", "medium"))),
                        tool=self.name,
                        asset=f"{comp.get('componentName', item.get('componentName', 'unknown'))}@{comp.get('componentVersionName', item.get('versionName', ''))}",
                        cve=vuln.get("vulnerabilityName") if str(vuln.get("vulnerabilityName", "")).startswith("CVE") else None,
                        cvss_score=vuln.get("overallScore"),
                        raw_data=item
                    ))
            else:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    findings.append(ParsedFinding(
                        title=row.get("Vulnerability ID", row.get("Vulnerability Name", "Black Duck Vulnerability")),
                        description=row.get("Description", row.get("Vulnerability Description", "")),
                        severity=self._map_severity(row.get("Severity", row.get("Security Risk", "medium"))),
                        tool=self.name,
                        asset=f"{row.get('Component Name', 'unknown')}@{row.get('Component Version', '')}",
                        cve=row.get("Vulnerability ID") if row.get("Vulnerability ID", "").startswith("CVE") else None,
                        cvss_score=self._parse_cvss(row.get("CVSS Score", row.get("Base Score"))),
                        raw_data=dict(row)
                    ))
        except:
            pass
        return findings

    def _parse_cvss(self, score: str) -> float | None:
        try:
            return float(score)
        except:
            return None

    def _map_severity(self, sev) -> str:
        if isinstance(sev, (int, float)):
            if sev >= 9.0: return "critical"
            if sev >= 7.0: return "high"
            if sev >= 4.0: return "medium"
            return "low"
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "ok": "info"}
        return mapping.get(str(sev).lower(), "medium")
