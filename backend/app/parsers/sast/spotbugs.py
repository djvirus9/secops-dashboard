import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SpotBugsParser(BaseParser):
    name = "spotbugs"
    display_name = "SpotBugs"
    category = ScannerCategory.SAST
    file_types = ["xml"]
    description = "SpotBugs Java bytecode static analysis tool"

    SEVERITY_MAP = {
        "1": "high",
        "2": "medium",
        "3": "low",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if filename and not filename.lower().endswith(".xml"):
                return False
            root = ET.fromstring(content)
            return root.tag in ("BugCollection", "bugCollection")
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return findings

        for bug in root.findall("BugInstance"):
            priority = bug.get("priority", "3")
            severity_str = self.SEVERITY_MAP.get(priority, "low")

            # Extract title from ShortMessage
            short_msg = bug.find("ShortMessage")
            title = short_msg.text if short_msg is not None else bug.get("type", "Unknown")

            # Build description from all text content
            desc_parts = []
            for elem in bug.iter():
                if elem.text and elem.text.strip():
                    desc_parts.append(elem.text.strip())
            description = "\n".join(desc_parts)

            # CWE
            cwe_id = None
            cwe_str = bug.get("cweid", "0")
            try:
                cwe_val = int(cwe_str)
                if cwe_val > 0:
                    cwe_id = cwe_val
            except (ValueError, TypeError):
                pass

            # Source location
            file_path = None
            line_number = None
            source = bug.find("SourceLine")
            if source is not None:
                file_path = source.get("sourcepath")
                start = source.get("start")
                if start and start.isdigit():
                    line_number = int(start)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="spotbugs",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data={"type": bug.get("type"), "priority": priority, "cweid": cwe_str},
            ))
        return findings
