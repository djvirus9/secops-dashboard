import json
import csv
import io
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CobaltIOParser(BaseParser):
    name = "cobaltio"
    display_name = "Cobalt.io"
    category = ScannerCategory.BUGBOUNTY
    file_types = ["json", "csv"]
    description = "Cobalt.io Pentest as a Service findings"

    def can_parse(self, content: str) -> bool:
        try:
            if "cobalt" in content.lower():
                return True
            data = json.loads(content)
            return "findings" in data or "pentest" in str(data).lower()
        except:
            return "Finding Title" in content or "Severity" in content and "Cobalt" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                items = data.get("findings", data.get("data", [data] if isinstance(data, dict) else data))
                for item in items:
                    findings.append(ParsedFinding(
                        title=item.get("title", item.get("name", "Cobalt.io Finding")),
                        description=item.get("description", item.get("proof_of_concept", "")),
                        severity=self._map_severity(item.get("severity", item.get("criticality", "medium"))),
                        tool=self.name,
                        asset=item.get("affected_asset", item.get("asset", "unknown")),
                        cwe=item.get("cwe"),
                        raw_data=item
                    ))
            else:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    findings.append(ParsedFinding(
                        title=row.get("Finding Title", row.get("Title", "Cobalt.io Finding")),
                        description=row.get("Description", row.get("Proof of Concept", "")),
                        severity=self._map_severity(row.get("Severity", row.get("Criticality", "medium"))),
                        tool=self.name,
                        asset=row.get("Affected Asset", row.get("Asset", "unknown")),
                        raw_data=dict(row)
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return mapping.get(str(sev).lower(), "medium")
