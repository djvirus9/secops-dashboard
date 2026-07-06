import csv
import io
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SolarAppscreenerParser(BaseParser):
    name = "solar_appscreener"
    display_name = "Solar AppScreener"
    category = ScannerCategory.SAST
    file_types = ["csv"]
    description = "Solar AppScreener SAST tool"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if filename and not filename.lower().endswith(".csv"):
                return False
            lines = content.strip().splitlines()
            if not lines:
                return False
            header = lines[0].lower()
            return "vulnerability" in header and "severity level" in header
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        for row in reader:
            title = row.get("Vulnerability", "").strip() or "Unknown"
            description = row.get("Description", "").strip()
            severity_str = row.get("Severity Level", "Info").strip()
            file_path = row.get("File", "").strip() or None
            line_str = row.get("Line", "").strip()
            recommendation = row.get("Recommendations", "").strip()
            references_str = row.get("Links", "").strip()

            line_number = None
            if line_str:
                # Line may be a range like "10-15"
                line_part = line_str.split("-")[0].strip()
                if line_part.isdigit():
                    line_number = int(line_part)

            references = [ref.strip() for ref in references_str.split() if ref.strip()] if references_str else []

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="solar_appscreener",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation=recommendation,
                references=references,
                raw_data=dict(row),
            ))
        return findings
