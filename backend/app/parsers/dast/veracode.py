import json
import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

XML_NAMESPACE = "https://www.veracode.com/schema/reports/export/1.0"
XML_NS = {"x": XML_NAMESPACE}

VC_SEVERITY_MAP = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

JSON_SEVERITY_MAP = {
    0: "info",
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


def _xml_parse(content: str) -> List[ParsedFinding]:
    findings = []
    root = ET.fromstring(content)

    # Handle namespace prefix
    def tag(local):
        return f"{{{XML_NAMESPACE}}}{local}"

    app_id = root.get("app_id", "")

    for category_node in root.iter(tag("category")):
        mitigation_parts = []
        for para in category_node.findall(f"{tag('recommendations')}/{tag('para')}"):
            text = para.get("text", "")
            if text:
                mitigation_parts.append(text)
        mitigation = "\n".join(mitigation_parts)

        # Static flaws
        for flaw in category_node.findall(
            f"{tag('cwe')}/{tag('staticflaws')}/{tag('flaw')}"
        ):
            sev_num = int(flaw.get("severity", "0"))
            severity_str = VC_SEVERITY_MAP.get(sev_num, "info")
            cwe_id_raw = flaw.get("cweid")
            cwe_id = int(cwe_id_raw) if cwe_id_raw and cwe_id_raw.isdigit() else None
            source_file = flaw.get("sourcefilepath", "") + flaw.get("sourcefile", "")
            line = flaw.get("line")
            title = flaw.get("categoryname", flaw.get("description", "Veracode Finding"))

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="veracode",
                description=flaw.get("description", ""),
                asset=source_file or "unknown",
                file_path=source_file or None,
                line_number=int(line) if line and line.isdigit() else None,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation=mitigation,
                raw_data=flaw.attrib,
            ))

        # Dynamic flaws
        for flaw in category_node.findall(
            f"{tag('cwe')}/{tag('dynamicflaws')}/{tag('flaw')}"
        ):
            sev_num = int(flaw.get("severity", "0"))
            severity_str = VC_SEVERITY_MAP.get(sev_num, "info")
            cwe_id_raw = flaw.get("cweid")
            cwe_id = int(cwe_id_raw) if cwe_id_raw and cwe_id_raw.isdigit() else None
            url = flaw.get("url", "unknown")
            title = flaw.get("categoryname", flaw.get("description", "Veracode Dynamic Finding"))

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="veracode",
                description=flaw.get("description", ""),
                asset=url,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation=mitigation,
                raw_data=flaw.attrib,
            ))

    # SCA findings from XML
    for component in root.iter(tag("component")):
        library = component.get("library", "")
        version = component.get("version", "")
        vendor = component.get("vendor", "")
        component_name = f"{vendor}:{library}" if vendor else library

        for vuln in component.findall(f"{tag('vulnerabilities')}/{tag('vulnerability')}"):
            cve_id = vuln.get("cve_id")
            severity_str = "medium"
            title = f"Vulnerable component: {component_name}:{version}"
            if cve_id:
                title = f"{cve_id} in {component_name}:{version}"

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="veracode",
                description=f"Vulnerable component {component_name} version {version}",
                asset=f"{component_name}:{version}",
                cve_id=cve_id,
                cwe_id=None,
                cvss_score=None,
                recommendation="Update to a non-vulnerable version.",
                raw_data={**component.attrib, **vuln.attrib},
            ))

    return findings


def _json_parse(content: str) -> List[ParsedFinding]:
    findings = []
    data = json.loads(content)
    items = data.get("findings", []) or data.get("_embedded", {}).get("findings", [])

    for vuln in items:
        if vuln.get("finding_status", {}).get("status", "") == "CLOSED":
            continue

        finding_details = vuln.get("finding_details", {})
        sev_num = finding_details.get("severity", 0)
        severity_str = JSON_SEVERITY_MAP.get(sev_num, "info")

        cwe_node = finding_details.get("cwe", {})
        cwe_id = cwe_node.get("id") if isinstance(cwe_node, dict) else None
        if cwe_id:
            try:
                cwe_id = int(cwe_id)
            except (ValueError, TypeError):
                cwe_id = None

        cve_id = None
        cve_list = finding_details.get("cve", [])
        if cve_list:
            if isinstance(cve_list, list):
                cve_id = cve_list[0] if cve_list else None
            else:
                cve_id = str(cve_list)

        scan_type = vuln.get("scan_type", "STATIC")
        if scan_type == "STATIC":
            file_path = finding_details.get("file_path", "")
            line_number = finding_details.get("file_line_number")
            asset = file_path or "unknown"
        else:
            asset = finding_details.get("url", "unknown")
            file_path = None
            line_number = None

        title = finding_details.get("finding_category", {}).get("name", "Veracode Finding")
        if isinstance(title, dict):
            title = title.get("name", "Veracode Finding")

        cvss_score = None
        cvss_raw = finding_details.get("cvss")
        if cvss_raw:
            try:
                cvss_score = float(cvss_raw)
            except (ValueError, TypeError):
                pass

        findings.append(ParsedFinding(
            title=str(title),
            severity=Severity.normalize(severity_str),
            tool="veracode",
            description=finding_details.get("description", ""),
            asset=asset,
            file_path=file_path,
            line_number=int(line_number) if line_number else None,
            cwe_id=cwe_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            recommendation="",
            raw_data=vuln,
        ))

    return findings


@ParserRegistry.register
class VeracodeParser(BaseParser):
    name = "veracode"
    display_name = "Veracode"
    category = ScannerCategory.DAST
    file_types = ["xml", "json"]
    description = "Veracode SAST/DAST/SCA scan results (XML or JSON)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        if filename and filename.lower().endswith(".xml"):
            return "veracode.com" in content or "detailedreport" in content.lower()
        if filename and filename.lower().endswith(".json"):
            try:
                data = json.loads(content)
                return "findings" in data or ("_embedded" in data and "findings" in data.get("_embedded", {}))
            except Exception:
                return False
        # Try XML first
        try:
            if "veracode.com" in content:
                return True
        except Exception:
            pass
        return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if filename and filename.lower().endswith(".json"):
            return _json_parse(content)
        # Default to XML
        try:
            return _xml_parse(content)
        except ET.ParseError:
            # Try JSON as fallback
            try:
                return _json_parse(content)
            except Exception:
                return []
