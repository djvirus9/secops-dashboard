import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

STRIDE_VALUES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


@ParserRegistry.register
class ThreatComposerParser(BaseParser):
    name = "threat_composer"
    display_name = "Threat Composer"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "AWS Threat Composer threat modeling tool"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "threats" in data
        except Exception:
            return False

    def _parse_metadata(self, metadata):
        severity = "info"
        impact = None
        for item in metadata or []:
            key = item.get("key", "")
            val = item.get("value", "")
            if key == "Priority" and val in ("Low", "Medium", "High"):
                severity = val
            elif key == "STRIDE":
                impact = ", ".join(STRIDE_VALUES.get(c, c) for c in (val if isinstance(val, list) else []))
        return severity, impact

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            if "threats" not in data:
                return findings

            for threat in data["threats"]:
                if "threatAction" not in threat:
                    continue
                title = threat["threatAction"]
                severity, impact = self._parse_metadata(threat.get("metadata", []))

                statement = threat.get("statement", "")
                description = f"**Threat**: {statement}" if statement else title
                if impact:
                    description += f"\n\n**Impact (STRIDE)**: {impact}"

                status = threat.get("status", "threatIdentified")
                tags = threat.get("tags", [])

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool=self.name,
                    description=description,
                    asset="unknown",
                    tags=tags if isinstance(tags, list) else [],
                    raw_data=threat,
                ))
        except Exception:
            pass
        return findings
