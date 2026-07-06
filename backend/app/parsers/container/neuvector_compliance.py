import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class NeuVectorComplianceParser(BaseParser):
    name = "neuvector_compliance"
    display_name = "NeuVector Compliance"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "NeuVector container compliance scan"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            # /v1/scan/workload/{id} format: {"report": {"checks": [...]}}
            if "report" in data and "checks" in data.get("report", {}):
                return True
            # /v1/host/{id}/compliance format: {"items": [...]}
            if "items" in data:
                items = data["items"]
                if isinstance(items, list) and items:
                    first = items[0]
                    return "test_number" in first or "category" in first
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        # Determine which key has the checks
        if "report" in data:
            checks = data["report"].get("checks", [])
        else:
            checks = data.get("items", [])

        for node in checks:
            if not isinstance(node, dict):
                continue

            test_number = node.get("test_number", "")
            category = node.get("category", "")
            description_text = node.get("description", "").rstrip()
            level = node.get("level", "")

            if not (test_number and category and description_text and level):
                continue

            unique_key = f"{node.get('type', '')}{category}{test_number}{description_text}"
            if unique_key in seen:
                continue
            seen.add(unique_key)

            title = f"{test_number} - {description_text}"
            severity = self._convert_severity(level)
            mitigation = node.get("remediation", "").rstrip()
            profile = node.get("profile", "profile unknown")

            full_description = f"{test_number} ({category}), {profile}:\n"
            full_description += f"{description_text}\n"
            full_description += f"Audit: {level}\n"
            if node.get("evidence"):
                full_description += f"Evidence:\n{node.get('evidence')}\n"
            if node.get("location"):
                full_description += f"Location:\n{node.get('location')}\n"
            full_description += f"Mitigation:\n{mitigation}\n"

            tags_raw = node.get("tags", [])
            tags = ["neuvector", "compliance"] + [str(t).rstrip() for t in tags_raw]

            messages = node.get("message", [])
            if messages:
                full_description += "Messages:\n"
                for m in messages:
                    full_description += f"{str(m).rstrip()}\n"

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity),
                tool="neuvector_compliance",
                description=full_description,
                asset=f"{category}_{test_number}",
                recommendation=mitigation,
                tags=tags,
                raw_data=node,
            ))

        return findings

    def _convert_severity(self, level: str) -> str:
        level_lower = level.lower()
        if level_lower == "high":
            return "high"
        if level_lower == "warn":
            return "medium"
        if level_lower == "info":
            return "low"
        if level_lower in ("pass", "note", "error"):
            return "info"
        return level
