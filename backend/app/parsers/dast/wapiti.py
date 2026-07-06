import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WapitiParser(BaseParser):
    name = "wapiti"
    display_name = "Wapiti"
    category = ScannerCategory.DAST
    file_types = ["xml"]
    description = "Wapiti web application vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            root = ET.fromstring(content)
            return "report" in root.tag.lower()
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        root = ET.fromstring(content)

        severity_mapping = {
            "4": "critical",
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "info",
        }

        target_url = "unknown"
        info_elem = root.find("report_infos")
        if info_elem is not None:
            for info in info_elem.findall("info"):
                if info.get("name") == "target":
                    target_url = info.text or "unknown"

        for vulnerability in root.findall("vulnerabilities/vulnerability"):
            category = vulnerability.get("name", "Unknown")
            description = vulnerability.findtext("description") or ""
            mitigation = vulnerability.findtext("solution") or ""

            cwe_id = None
            references = []
            for reference in vulnerability.findall("references/reference"):
                ref_title = reference.findtext("title") or ""
                ref_url = reference.findtext("url") or ""
                if ref_title.startswith("CWE"):
                    cwe_match = re.search(r"CWE-(\d+)", ref_title, re.IGNORECASE)
                    if cwe_match:
                        cwe_id = int(cwe_match.group(1))
                if ref_url:
                    references.append(ref_url)

            for entry in vulnerability.findall("entries/entry"):
                info_text = entry.findtext("info") or ""
                title = f"{category}: {info_text}" if info_text else category
                num_severity = entry.findtext("level") or "0"
                severity_str = severity_mapping.get(num_severity, "info")

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity_str),
                    tool="wapiti",
                    description=description,
                    asset=target_url,
                    cwe_id=cwe_id,
                    cve_id=None,
                    cvss_score=None,
                    recommendation=mitigation,
                    references=references,
                    raw_data={
                        "category": category,
                        "info": info_text,
                        "level": num_severity,
                        "http_request": entry.findtext("http_request") or "",
                    },
                ))

        return findings
