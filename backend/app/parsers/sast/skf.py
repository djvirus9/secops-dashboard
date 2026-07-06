import csv
import io
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SKFParser(BaseParser):
    name = "skf"
    display_name = "Security Knowledge Framework"
    category = ScannerCategory.SAST
    file_types = ["csv"]
    description = "Security Knowledge Framework (SKF) sprint summary export"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if filename and not filename.lower().endswith(".csv"):
                return False
            lines = content.strip().splitlines()
            if not lines:
                return False
            header = lines[0].lower()
            return "title" in header and "description" in header and "mitigation" in header
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        reader = csv.reader(
            io.StringIO(content), delimiter=",", quotechar='"', escapechar="\\"
        )

        column_names = {}
        for row_number, row in enumerate(reader):
            if row_number == 0:
                for idx, col in enumerate(row):
                    column_names[idx] = col.lower()
                continue

            row_data = {column_names.get(i, ""): val for i, val in enumerate(row)}
            title = row_data.get("title", "").strip()
            description = row_data.get("description", "").strip()
            mitigation = row_data.get("mitigation", "").strip()

            if not title:
                continue

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize("info"),
                tool="skf",
                description=description,
                asset="unknown",
                file_path=None,
                line_number=None,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation=mitigation,
                raw_data=row_data,
            ))
        return findings
