import csv
import io
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AlertLogicParser(BaseParser):
    name = "alertlogic"
    display_name = "Alert Logic"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["csv"]
    description = "Alert Logic vulnerability scan findings"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            first_line = content.strip().lstrip("﻿").splitlines()[0].lower()
            return "vulnerability" in first_line and "severity" in first_line and "asset name" in first_line
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            if content.startswith("﻿"):
                content = content[1:]
            reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
            for row in reader:
                vuln = (row.get("Vulnerability") or "").strip()
                if not vuln:
                    continue

                severity = (row.get("Severity") or "info").strip()
                title = vuln[:497] + "..." if len(vuln) > 500 else vuln

                description_parts = []
                for field in ("Description", "Evidence", "Operating System", "Category",
                              "Service", "First Seen", "Last Scanned", "CISA Known Exploited"):
                    val = (row.get(field) or "").strip()
                    if val:
                        description_parts.append(f"**{field}**: {val}")
                description = "\n\n".join(description_parts)

                cve = (row.get("CVE") or "").strip()
                asset = (row.get("Asset Name") or row.get("IP Address") or "unknown").strip()
                recommendation = (row.get("Resolution") or "").strip()

                cvss_score = None
                cvss_raw = (row.get("CVSS Score") or "").strip()
                try:
                    cvss_score = float(cvss_raw) if cvss_raw else None
                except ValueError:
                    pass

                tags = []
                if (row.get("CISA Known Exploited") or "").strip().lower() == "yes":
                    tags.append("cisa-known-exploited")

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    recommendation=recommendation,
                    cve_id=cve if cve.upper().startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    tags=tags,
                    raw_data=dict(row),
                ))
        except Exception:
            pass
        return findings
