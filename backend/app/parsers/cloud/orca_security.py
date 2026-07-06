import csv
import io
import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _orca_score_to_severity(score) -> str:
    """Map Orca numeric score (0-10) to severity string."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s >= 0.1:
        return "low"
    return "info"


@ParserRegistry.register
class OrcaSecurityParser(BaseParser):
    name = "orca_security"
    display_name = "Orca Security"
    category = ScannerCategory.CLOUD
    file_types = ["json", "csv"]
    description = "Orca Security cloud risk platform"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        stripped = content.strip()
        # JSON array of Orca alerts
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
                if isinstance(data, list) and data:
                    first = data[0]
                    return isinstance(first, dict) and ("OrcaScore" in first or "Title" in first)
            except Exception:
                pass
        # CSV with Orca-specific headers
        try:
            first_line = stripped.splitlines()[0].lower()
            return "orcascore" in first_line or ("title" in first_line and "category" in first_line and "source" in first_line)
        except Exception:
            pass
        return False

    def _parse_json(self, content: str) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        for item in data:
            if not isinstance(item, dict):
                continue
            title = (item.get("Title") or "Orca Alert").strip()
            score = item.get("OrcaScore")
            sev = _orca_score_to_severity(score)
            category = (item.get("Category") or "").strip()
            source = (item.get("Source") or "").strip()
            status = (item.get("Status") or "").strip()

            cloud_account = item.get("CloudAccount") or {}
            cloud_name = (cloud_account.get("Name") or "").strip()
            inventory = item.get("Inventory") or {}
            inventory_name = (inventory.get("Name") or "").strip()

            asset = inventory_name or cloud_name or "unknown"

            description = f"**Category**: {category}\n**Source**: {source}\n**Status**: {status}"
            if cloud_name:
                description += f"\n**Cloud Account**: {cloud_name}"
            if score is not None:
                description += f"\n**Orca Score**: {score}"

            labels = item.get("Labels") or []
            tags = labels if isinstance(labels, list) else []

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(sev),
                tool=self.name,
                description=description,
                asset=asset,
                tags=tags,
                raw_data=item,
            ))
        return findings

    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            title = (row.get("Title") or "Orca Alert").strip()
            if not title:
                continue
            score = row.get("OrcaScore") or row.get("Score") or ""
            sev = _orca_score_to_severity(score)
            asset = (row.get("Asset Name") or row.get("Inventory") or "unknown").strip()
            description_parts = []
            for field in ("Category", "Source", "Status", "Cloud Account", "Description"):
                val = (row.get(field) or "").strip()
                if val:
                    description_parts.append(f"**{field}**: {val}")
            description = "\n".join(description_parts)
            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(sev),
                tool=self.name,
                description=description,
                asset=asset,
                raw_data=dict(row),
            ))
        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        stripped = content.strip()
        try:
            if stripped.startswith("["):
                return self._parse_json(stripped)
            return self._parse_csv(content)
        except Exception:
            pass
        return []
