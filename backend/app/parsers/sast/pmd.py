import csv
import io
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PmdParser(BaseParser):
    name = "pmd"
    display_name = "PMD"
    category = ScannerCategory.SAST
    file_types = ["csv"]
    description = "PMD static code analyzer for Java and other languages"

    PRIORITY_MAP = {
        "1": "info",
        "2": "low",
        "3": "medium",
        "4": "high",
        "5": "critical",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if filename and not filename.lower().endswith(".csv"):
                return False
            lines = content.strip().splitlines()
            if not lines:
                return False
            header = lines[0].lower()
            return "rule" in header and "priority" in header and "file" in header
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        for row in reader:
            rule = row.get("Rule", "Unknown Rule")
            priority = str(row.get("Priority", "1")).strip()
            severity_str = self.PRIORITY_MAP.get(priority, "info")

            description = ""
            description += f"Description: {row.get('Description', '').strip()}\n"
            description += f"Rule set: {row.get('Rule set', '').strip()}\n"
            description += f"Problem: {row.get('Problem', '').strip()}\n"
            description += f"Package: {row.get('Package', '').strip()}\n"

            file_path = row.get("File", None)
            line_str = row.get("Line", None)
            line_number = None
            if line_str:
                try:
                    line_number = int(line_str)
                except ValueError:
                    pass

            findings.append(ParsedFinding(
                title=f"PMD rule {rule}",
                severity=Severity.normalize(severity_str),
                tool="pmd",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data=dict(row),
            ))
        return findings
