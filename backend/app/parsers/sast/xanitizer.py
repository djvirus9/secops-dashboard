import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class XanitizerParser(BaseParser):
    name = "xanitizer"
    display_name = "Xanitizer"
    category = ScannerCategory.SAST
    file_types = ["xml"]
    description = "Xanitizer SAST tool for Java web applications"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            root = ET.fromstring(content)
            return "XanitizerFindingsList" in root.tag
        except Exception:
            return False

    def _resolve_severity(self, finding: ET.Element) -> str:
        rating_elem = finding.find("rating")
        if rating_elem is None or not rating_elem.text:
            return "info"
        try:
            rating = float(rating_elem.text)
        except (ValueError, TypeError):
            return "info"
        if rating == 0:
            return "info"
        if rating < 4:
            return "low"
        if rating < 7:
            return "medium"
        if rating < 9:
            return "high"
        return "critical"

    def _resolve_cwe(self, finding: ET.Element) -> Optional[int]:
        cwe_elem = finding.find("cweNumber")
        if cwe_elem is None or not cwe_elem.text:
            return None
        cwe_text = cwe_elem.text.strip()
        if cwe_text.upper().startswith("CWE-"):
            cwe_text = cwe_text[4:].replace(",", "").replace(".", "").strip()
        try:
            return int(cwe_text)
        except (ValueError, TypeError):
            return None

    def _get_text(self, elem: Optional[ET.Element]) -> str:
        if elem is None:
            return ""
        return (elem.text or "").strip()

    def _generate_file_path(self, finding: ET.Element) -> Optional[str]:
        end_node = finding.find("endNode")
        if end_node is not None and end_node.get("relativePath"):
            return end_node.get("relativePath")
        node = finding.find("node")
        if node is not None and node.get("relativePath"):
            return node.get("relativePath")
        pkg = finding.find("package")
        file_elem = finding.find("file")
        if pkg is not None and file_elem is not None:
            return "{}/{}".format(
                (pkg.text or "").replace(".", "/"),
                file_elem.text or "",
            )
        if file_elem is not None:
            return file_elem.text
        return None

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return findings

        for finding in root.findall("finding"):
            problem_type_elem = finding.find("problemType")
            title = self._get_text(problem_type_elem) or "Unknown"

            line_elem = finding.find("line")
            line_number = None
            if line_elem is not None and line_elem.text:
                try:
                    val = int(line_elem.text)
                    if val > 0:
                        line_number = val
                except (ValueError, TypeError):
                    pass

            description_parts = []
            desc_elem = finding.find("description")
            if desc_elem is not None and desc_elem.text:
                description_parts.append(f"**Description:**\n{desc_elem.text.strip()}")

            # Add node/flow information
            start_node = finding.find("startNode")
            end_node = finding.find("endNode")
            node = finding.find("node")

            if start_node is not None and end_node is not None:
                description_parts.append(
                    f"\n**Starting at:** {start_node.get('classFQN', '')} - **Line** {start_node.get('lineNo', '')}"
                )
                description_parts.append(
                    f"**Ending at:** {end_node.get('classFQN', '')} - **Line** {end_node.get('lineNo', '')}"
                )
            elif node is not None:
                line_no = node.get("lineNo")
                location = node.get("classFQN") or node.get("relativePath", "")
                if line_no and int(line_no) > 0:
                    description_parts.append(f"\n**Finding at:** {location} - **Line** {line_no}")
                else:
                    description_parts.append(f"\n**Finding at:** {location}")

            description = "\n".join(description_parts)

            # Check for CVE in description
            cve_id = None
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", description)
            if cve_match:
                cve_id = cve_match.group()

            # Build full title
            pkg_elem = finding.find("package")
            cls_elem = finding.find("class")
            file_elem = finding.find("file")
            if pkg_elem is not None and cls_elem is not None:
                if line_number:
                    full_title = f"{title} ({pkg_elem.text}.{cls_elem.text}:{line_number})"
                else:
                    full_title = f"{title} ({pkg_elem.text}.{cls_elem.text})"
            elif file_elem is not None:
                if line_number:
                    full_title = f"{title} ({file_elem.text}:{line_number})"
                else:
                    full_title = f"{title} ({file_elem.text})"
            else:
                full_title = title

            file_path = self._generate_file_path(finding)

            findings.append(ParsedFinding(
                title=full_title,
                severity=Severity.normalize(self._resolve_severity(finding)),
                tool="xanitizer",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=self._resolve_cwe(finding),
                cve_id=cve_id,
                cvss_score=None,
                recommendation="",
                raw_data={"problemType": title},
            ))
        return findings
