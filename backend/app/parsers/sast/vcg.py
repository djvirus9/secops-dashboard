import csv
import io
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class VCGParser(BaseParser):
    name = "vcg"
    display_name = "VisualCodeGrepper"
    category = ScannerCategory.SAST
    file_types = ["csv", "xml"]
    description = "VisualCodeGrepper (VCG) static code analysis tool"

    PRIORITY_MAP = {
        1: "critical",
        2: "high",
        3: "medium",
        4: "low",
        5: "low",
        6: "info",
        7: "info",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if filename:
                fname = filename.lower()
                if fname.endswith(".xml"):
                    root = ET.fromstring(content)
                    return "vcg" in root.tag.lower() or root.find("CodeIssue") is not None
                if fname.endswith(".csv"):
                    lines = content.strip().splitlines()
                    return len(lines) > 0
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if filename and filename.lower().endswith(".xml"):
            return self._parse_xml(content)
        return self._parse_csv(content)

    def _priority_to_severity(self, priority: int) -> str:
        return self.PRIORITY_MAP.get(priority, "info")

    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return findings

        for issue in root.findall("CodeIssue"):
            def _text(tag):
                elem = issue.find(tag)
                return elem.text if elem is not None and elem.text else None

            priority_str = _text("Priority")
            try:
                priority = int(float(priority_str)) if priority_str else 6
            except (ValueError, TypeError):
                priority = 6

            severity_str = self._priority_to_severity(priority)
            title = _text("Title") or "Unknown"
            description_parts = []
            sev = _text("Severity")
            desc = _text("Description")
            fname = _text("FileName")
            line = _text("Line")
            code_line = _text("CodeLine")

            if sev:
                description_parts.append(f"Severity: {sev}")
            if desc:
                description_parts.append(f"Description: {desc}")
            if fname:
                description_parts.append(f"FileName: {fname}")
            if line:
                description_parts.append(f"Line: {line}")
            if code_line:
                description_parts.append(f"CodeLine: {code_line}")

            line_number = None
            if line:
                try:
                    line_number = int(line)
                except ValueError:
                    pass

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="vcg",
                description="\n".join(description_parts),
                asset=fname or "unknown",
                file_path=fname,
                line_number=line_number,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data={"title": title, "priority": priority},
            ))
        return findings

    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        # Columns: Priority, Severity, Title, Description, FileName, Line, CodeLine
        reader = csv.reader(io.StringIO(content), delimiter=",", quotechar='"')
        for row in reader:
            if len(row) < 3:
                continue
            try:
                priority = int(float(row[0].strip()))
            except (ValueError, IndexError):
                priority = 6

            severity_str = self._priority_to_severity(priority)
            title = row[2].strip() if len(row) > 2 else "Unknown"
            sev = row[1].strip() if len(row) > 1 else ""
            desc = row[3].strip() if len(row) > 3 else ""
            fname = row[4].strip() if len(row) > 4 else None
            line_str = row[5].strip() if len(row) > 5 else None
            code_line = row[6].strip() if len(row) > 6 else ""

            description_parts = []
            if sev:
                description_parts.append(f"Severity: {sev}")
            if desc:
                description_parts.append(f"Description: {desc}")
            if fname:
                description_parts.append(f"FileName: {fname}")
            if line_str:
                description_parts.append(f"Line: {line_str}")
            if code_line:
                description_parts.append(f"CodeLine: {code_line}")

            line_number = None
            if line_str:
                try:
                    line_number = int(line_str)
                except ValueError:
                    pass

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="vcg",
                description="\n".join(description_parts),
                asset=fname or "unknown",
                file_path=fname,
                line_number=line_number,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data={"row": row},
            ))
        return findings
