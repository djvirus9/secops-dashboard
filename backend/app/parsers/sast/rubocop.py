import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class RubocopParser(BaseParser):
    name = "rubocop"
    display_name = "RuboCop"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Ruby static code analyzer and formatter"

    SEVERITY_MAP = {
        "info": "info",
        "refactor": "medium",
        "convention": "medium",
        "warning": "medium",
        "error": "high",
        "fatal": "critical",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "files" in data and "summary" in data and isinstance(data.get("files"), list)
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for vuln_file in data.get("files", []):
            path = vuln_file.get("path", "unknown")
            for offense in vuln_file.get("offenses", []):
                # Only include security-related offenses
                cop_name = offense.get("cop_name", "")
                if not cop_name.lower().startswith("security"):
                    continue

                location = offense.get("location", {})
                line_number = None
                start_line = location.get("start_line")
                if start_line:
                    try:
                        line_number = int(start_line)
                    except (ValueError, TypeError):
                        pass

                message = offense.get("message", "")
                description = f"**Message**: {message}\n"
                description += f"**Is correctable?**: `{offense.get('correctable', False)}`\n"
                description += f"**Cop**: `{cop_name}`\n"

                severity_key = offense.get("severity", "convention").lower()
                severity_str = self.SEVERITY_MAP.get(severity_key, "medium")

                findings.append(ParsedFinding(
                    title=message,
                    severity=Severity.normalize(severity_str),
                    tool="rubocop",
                    description=description,
                    asset=path,
                    file_path=path,
                    line_number=line_number,
                    cwe_id=None,
                    cve_id=None,
                    cvss_score=None,
                    recommendation="",
                    raw_data=offense,
                ))
        return findings
