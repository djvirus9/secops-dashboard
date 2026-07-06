import json
from datetime import datetime, timedelta
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class XeolParser(BaseParser):
    name = "xeol"
    display_name = "Xeol"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Xeol end-of-life package scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            if "matches" not in data:
                return False
            matches = data["matches"]
            if not isinstance(matches, list) or len(matches) == 0:
                return True  # empty matches is valid xeol
            first = matches[0]
            return "Cycle" in first or "artifact" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []

        distro = data.get("distro", {})

        for match in data.get("matches", []):
            cycle = match.get("Cycle", {})
            artifact = match.get("artifact", {})

            product_name = cycle.get("ProductName", "Unknown Product")
            title = f"{product_name} EOL Information"

            eol_str = cycle.get("Eol", "")
            severity = self._compute_severity(eol_str)

            description_lines = [
                f"**Product Name:** {cycle.get('ProductName', 'N/A')}",
                f"**Release Cycle:** {cycle.get('ReleaseCycle', 'N/A')}",
                f"**EOL Date:** {eol_str or 'N/A'}",
                f"**Latest Release Date:** {cycle.get('LatestReleaseDate', 'N/A')}",
                f"**Release Date:** {cycle.get('ReleaseDate', 'N/A')}",
                f"**Artifact Name:** {artifact.get('name', 'N/A')}",
                f"**Artifact Version:** {artifact.get('version', 'N/A')}",
                f"**Artifact Type:** {artifact.get('type', 'N/A')}",
                f"**Package URL:** {artifact.get('purl', 'N/A')}",
                f"**Distro Name:** {distro.get('name', 'N/A')}",
                f"**Distro Version:** {distro.get('version', 'N/A')}",
            ]

            licenses = artifact.get("licenses", [])
            if licenses:
                description_lines.append(f"**Licenses:** {', '.join(licenses)}")

            locations = artifact.get("locations", [])
            if locations:
                loc_info = [f"Path: {loc.get('path', '')}" for loc in locations]
                description_lines.append("**Locations:**\n" + "\n".join(loc_info))

            description = "\n".join(description_lines)

            refs = []
            permalink = cycle.get("ProductPermalink", "")
            if permalink:
                refs.append(permalink)
            refs.append("https://www.xeol.io/explorer")

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity),
                tool="xeol",
                description=description,
                asset=artifact.get("name", "unknown"),
                cwe_id=672,
                references=refs,
                tags=["xeol", "eol", artifact.get("type", "")],
                raw_data=match,
            ))

        return findings

    def _compute_severity(self, eol_str: str) -> str:
        if not eol_str:
            return "info"
        try:
            eol_date = datetime.strptime(eol_str, "%Y-%m-%d")
            now = datetime.now()
            if eol_date >= now:
                return "info"
            delta = now - eol_date
            if delta <= timedelta(weeks=2):
                return "low"
            if delta <= timedelta(weeks=4):
                return "medium"
            if delta <= timedelta(weeks=6):
                return "high"
            return "critical"
        except Exception:
            return "info"
