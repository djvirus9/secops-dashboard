import csv
import io
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PicusParser(BaseParser):
    name = "picus"
    display_name = "Picus"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["csv"]
    description = "Picus Breach and Attack Simulation (BAS) platform"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            first_line = content.strip().splitlines()[0].lower()
            return "threatname" in first_line and "threatpreventionresult" in first_line
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            if content.startswith("﻿"):
                content = content[1:]
            reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
            for row in reader:
                def get(key):
                    return (row.get(key) or "").strip()

                threat_name = get("threatName")
                action_name = get("actionName")
                if not threat_name:
                    continue

                title = f"{threat_name} - {action_name}" if action_name else threat_name
                if len(title) > 500:
                    title = title[:497] + "..."

                severity = get("threatSeverity")
                description_parts = [
                    f"**Threat**: {threat_name}",
                    f"**Action**: {action_name}",
                    f"**Action Description**: {get('actionDescription')}",
                    f"**Attack Category**: {get('attackCategory')}",
                    f"**Prevention Result**: {get('threatPreventionResult')}",
                    f"**MITRE Tactic**: {get('actionMitreTactic')}",
                    f"**MITRE Technique**: {get('actionMitreTechnique')}",
                    f"**Affected OS**: {get('affectedOs')}",
                ]
                description = "\n".join(p for p in description_parts if not p.endswith(": "))

                cve_raw = get("cve")
                cve_id = None
                if cve_raw:
                    cves = [c.strip() for c in cve_raw.split(",") if c.strip()]
                    cve_id = cves[0] if cves else None

                tags = []
                for tag_field in ("actionMitreTactic", "actionMitreTechnique", "attackCategory"):
                    val = get(tag_field)
                    if val:
                        tags.append(val)

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool=self.name,
                    description=description,
                    asset=get("affectedProducts") or get("affectedPlatforms") or "unknown",
                    cve_id=cve_id,
                    tags=tags,
                    raw_data=dict(row),
                ))
        except Exception:
            pass
        return findings
