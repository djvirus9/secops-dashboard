import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class FortifyParser(BaseParser):
    name = "fortify"
    display_name = "Fortify"
    category = ScannerCategory.SAST
    file_types = ["xml", "fpr", "json"]
    description = "HP/Micro Focus Fortify Static Code Analyzer"

    def can_parse(self, content: str) -> bool:
        return "FVDL" in content or "Fortify" in content or "ReportDefinition" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                for vuln in data.get("vulnerabilities", []):
                    findings.append(self._create_finding(vuln))
            else:
                root = ET.fromstring(content)
                ns = {"fvdl": "xmlns://www.fortifysoftware.com/schema/fvdl"}
                for vuln in root.findall(".//fvdl:Vulnerability", ns) or root.findall(".//Vulnerability"):
                    findings.append(self._parse_xml_vuln(vuln, ns))
        except:
            pass
        return findings

    def _create_finding(self, vuln: dict) -> ParsedFinding:
        return ParsedFinding(
            title=vuln.get("category", vuln.get("type", "Fortify Finding")),
            description=vuln.get("abstract", vuln.get("explanation", "")),
            severity=self._map_severity(vuln.get("frilesriority", vuln.get("severity", "medium"))),
            tool=self.name,
            asset=vuln.get("primaryLocation", {}).get("file", "unknown"),
            cwe=vuln.get("cwe"),
            raw_data=vuln
        )

    def _parse_xml_vuln(self, vuln, ns) -> ParsedFinding:
        cat_el = vuln.find(".//Category") or vuln.find("Category")
        category = cat_el.text if cat_el is not None else "Fortify Finding"
        abstract_el = vuln.find(".//Abstract") or vuln.find("Abstract")
        abstract = abstract_el.text if abstract_el is not None else ""
        file_el = vuln.find(".//SourceLocation") or vuln.find("SourceLocation")
        file_path = file_el.get("path", "unknown") if file_el is not None else "unknown"
        return ParsedFinding(
            title=category,
            description=abstract,
            severity="medium",
            tool=self.name,
            asset=file_path,
            raw_data={"xml": True}
        )

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
