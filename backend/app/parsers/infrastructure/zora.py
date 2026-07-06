import csv
import io
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ZoraParser(BaseParser):
    name = "zora"
    display_name = "Zora"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["csv"]
    description = "Zora Kubernetes vulnerability scanner (CSV export)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            first_line = content.strip().splitlines()[0].lower()
            return "title" in first_line and "severity" in first_line and "source" in first_line
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
            for row in reader:
                title = row.get("title", "").strip()
                if not title:
                    continue
                raw_severity = (row.get("severity") or "").strip()
                description = (
                    f"**Source**: {row.get('source', '')}\n"
                    f"**Image**: {row.get('image', '')}\n"
                    f"**ID**: {row.get('id', '')}\n"
                    f"**Details**: {row.get('description', '')}\n"
                )
                vuln_id = row.get("id", "").strip()
                asset = row.get("image") or row.get("source") or "unknown"
                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(raw_severity),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    cve_id=vuln_id if vuln_id.upper().startswith("CVE-") else None,
                    raw_data=dict(row),
                ))
        except Exception:
            pass
        return findings
