import json
import textwrap
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _convert_severity(cobalt_severity: str) -> str:
    mapping = {
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get((cobalt_severity or "").lower(), "info")


@ParserRegistry.register
class ApiCobaltParser(BaseParser):
    name = "api_cobalt"
    display_name = "Cobalt.io API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Cobalt.io pentest platform API export"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and "data" in data
                and isinstance(data["data"], list)
                and data["data"]
                and "resource" in data["data"][0]
                and "state" in data["data"][0].get("resource", {})
            )
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for entry in data.get("data", []):
                resource = entry.get("resource", {})
                links = entry.get("links", {})

                title = resource.get("title", "Cobalt Finding")
                title = textwrap.shorten(title, width=511, placeholder="...")

                severity_str = resource.get("severity", "info")
                state = resource.get("state", "new")

                cobalt_url = links.get("ui", {}).get("url", "")
                description = resource.get("description", "")
                impact = resource.get("impact", "")
                likelihood = resource.get("likelihood", "")
                if impact or likelihood:
                    description += f"\n\n**Impact**: {impact}\n**Likelihood**: {likelihood}"
                if cobalt_url:
                    description += f"\n\n**Cobalt.io**: {cobalt_url}"

                mitigation = resource.get("suggested_fix", "")
                affected_targets = resource.get("affected_targets", [])
                asset = affected_targets[0] if affected_targets else "unknown"

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(_convert_severity(severity_str)),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    recommendation=mitigation,
                    raw_data=resource,
                ))
        except Exception:
            pass
        return findings
