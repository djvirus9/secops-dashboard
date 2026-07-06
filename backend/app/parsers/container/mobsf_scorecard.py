import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class MobSFScorecardParser(BaseParser):
    name = "mobsf_scorecard"
    display_name = "MobSF Scorecard"
    category = ScannerCategory.MOBILE
    file_types = ["json"]
    description = "MobSF (Mobile Security Framework) security scorecard scanner"

    # MobSF severity mapping
    _SEVERITY_MAP = {
        "high": "high",
        "warning": "medium",
        "info": "info",
        "secure": "info",
        "hotspot": "low",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            appsec = data.get("appsec", {})
            if not isinstance(appsec, dict):
                return False
            # MobSF scorecard has high/warning/info/secure/hotspot keys in appsec
            return any(k in appsec for k in ("high", "warning", "info", "secure", "hotspot"))
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        appsec = data.get("appsec", {})
        app_name = appsec.get("app_name", data.get("app_name", "unknown"))
        package_name = data.get("package_name", data.get("bundle_id", "unknown"))

        for mobsf_severity, dd_severity in self._SEVERITY_MAP.items():
            for item in appsec.get(mobsf_severity, []):
                if not isinstance(item, dict):
                    continue

                section = str(item.get("section", ""))
                title = str(item.get("title", ""))
                description = str(item.get("description", ""))

                unique_key = f"{mobsf_severity}-{section}-{title}-{description}"
                if unique_key in seen:
                    continue
                seen.add(unique_key)

                full_description = f"**Category:** {section}\n\n{description}" if section else description

                findings.append(ParsedFinding(
                    title=title or f"MobSF {mobsf_severity} finding",
                    severity=Severity.normalize(dd_severity),
                    tool="mobsf_scorecard",
                    description=full_description,
                    asset=package_name or app_name or "unknown",
                    cwe_id=919,  # Weaknesses in Mobile Applications
                    tags=["mobsf", section, mobsf_severity],
                    raw_data=item,
                ))

        return findings
