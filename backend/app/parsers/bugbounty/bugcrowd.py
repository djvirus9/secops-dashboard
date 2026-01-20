import json
import csv
import io
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class BugcrowdParser(BaseParser):
    name = "bugcrowd"
    display_name = "Bugcrowd"
    category = ScannerCategory.BUGBOUNTY
    file_types = ["json", "csv"]
    description = "Bugcrowd crowdsourced security reports"

    def can_parse(self, content: str) -> bool:
        try:
            if "bugcrowd" in content.lower():
                return True
            data = json.loads(content)
            return "submissions" in data or "vulnerability_references" in str(data)
        except:
            return "Title" in content and "Severity" in content and "Target" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                submissions = data.get("submissions", data.get("data", [data] if isinstance(data, dict) else data))
                for sub in submissions:
                    findings.append(ParsedFinding(
                        title=sub.get("title", sub.get("name", "Bugcrowd Submission")),
                        description=sub.get("description", sub.get("vulnerability_description", "")),
                        severity=self._map_severity(sub.get("severity", sub.get("priority", "medium"))),
                        tool=self.name,
                        asset=sub.get("target", sub.get("asset", "unknown")),
                        cwe=sub.get("cwe"),
                        raw_data=sub
                    ))
            else:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    findings.append(ParsedFinding(
                        title=row.get("Title", row.get("title", "Bugcrowd Submission")),
                        description=row.get("Description", row.get("description", "")),
                        severity=self._map_severity(row.get("Severity", row.get("Priority", "medium"))),
                        tool=self.name,
                        asset=row.get("Target", row.get("Asset", "unknown")),
                        raw_data=dict(row)
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev) -> str:
        if isinstance(sev, int):
            if sev >= 4: return "critical"
            if sev >= 3: return "high"
            if sev >= 2: return "medium"
            return "low"
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "p1": "critical", "p2": "high", "p3": "medium", "p4": "low"}
        return mapping.get(str(sev).lower(), "medium")
