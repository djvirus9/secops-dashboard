import json
import re
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PopeyeParser(BaseParser):
    name = "popeye"
    display_name = "Popeye"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Popeye Kubernetes cluster sanitizer"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "popeye" in data and "sanitizers" in data["popeye"]
        except Exception:
            return False

    def _level_to_severity(self, level: int) -> Severity:
        if level == 1:
            return Severity.INFO
        if level == 2:
            return Severity.LOW
        return Severity.HIGH

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        seen = set()
        try:
            data = json.loads(content)
            for sanitizer in data["popeye"]["sanitizers"]:
                issues = sanitizer.get("issues") or {}
                sanitizer_name = sanitizer.get("sanitizer", "unknown")
                for issue_group, issue_list in issues.items():
                    for issue in issue_list:
                        level = issue.get("level", 0)
                        if level == 0:
                            continue
                        message = issue.get("message", "")
                        title = f"{sanitizer_name} {issue_group} {message}"
                        description = (
                            f"**Sanitizer**: {sanitizer_name}\n\n"
                            f"**Resource**: {issue_group}\n\n"
                            f"**Group**: {issue.get('group', '')}\n\n"
                            f"**Message**: {message}"
                        )
                        # Extract POP-NNN id from message if present
                        pop_id = None
                        m = re.search(r"\[(POP-\d+)\]", message)
                        if m:
                            pop_id = m.group(1)

                        dupe_key = title
                        if dupe_key in seen:
                            continue
                        seen.add(dupe_key)

                        findings.append(ParsedFinding(
                            title=title,
                            severity=self._level_to_severity(level),
                            tool=self.name,
                            description=description,
                            asset=issue_group,
                            tags=[pop_id] if pop_id else [],
                            raw_data=issue,
                        ))
        except Exception:
            pass
        return findings
