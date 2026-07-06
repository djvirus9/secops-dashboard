import csv
import io
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TrustwaveParser(BaseParser):
    name = "trustwave"
    display_name = "Trustwave"
    category = ScannerCategory.DAST
    file_types = ["csv"]
    description = "Trustwave web vulnerability scanner (CSV)"

    SEVERITY_MAP = {
        "I": "info",
        "L": "low",
        "M": "medium",
        "H": "high",
        "C": "critical",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            first_line = content.strip().splitlines()[0]
            reader = csv.DictReader(io.StringIO(content))
            fields = reader.fieldnames or []
            required = {"Vulnerability Name", "Severity", "Description"}
            return required.issubset(set(fields))
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content))

        seen = set()
        for row in reader:
            title = row.get("Vulnerability Name", "Unknown")
            description = row.get("Description", "")
            severity_code = row.get("Severity", "L")
            severity_str = self.SEVERITY_MAP.get(severity_code.strip().upper(), "low")

            cve_raw = row.get("CVE", "")
            cve_id = cve_raw.strip() if cve_raw and cve_raw.strip().upper().startswith("CVE") else None

            # Build the asset from domain/IP + port + protocol
            host = row.get("Domain", "").strip() or row.get("IP", "").strip() or "unknown"
            port = row.get("Port", "").strip()
            protocol = row.get("Protocol", "").strip()
            if protocol and host != "unknown":
                asset = f"{protocol}://{host}:{port}" if port else f"{protocol}://{host}"
            elif host != "unknown":
                asset = f"{host}:{port}" if port else host
            else:
                asset = "unknown"

            dedup = f"{title}|{severity_str}|{description[:100]}"
            if dedup in seen:
                continue
            seen.add(dedup)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="trustwave",
                description=description,
                asset=asset,
                cwe_id=None,
                cve_id=cve_id,
                cvss_score=None,
                recommendation=row.get("Remediation", ""),
                references=[row.get("Evidence", "")] if row.get("Evidence") else [],
                raw_data=dict(row),
            ))

        return findings
