import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WhispersParser(BaseParser):
    name = "whispers"
    display_name = "Whispers"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "Whispers hardcoded secrets scanner"

    SEVERITY_MAP = {
        # Whispers 2.1
        "BLOCKER": "critical",
        "CRITICAL": "high",
        "MAJOR": "medium",
        "MINOR": "low",
        "INFO": "info",
        # Whispers 2.2
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return (
                "message" in first
                and "key" in first
                and "value" in first
                and "file" in first
                and "line" in first
                and "severity" in first
            )
        except Exception:
            return False

    @staticmethod
    def _mask(text: str, n_plain: int = 4) -> str:
        length = len(text)
        if length <= n_plain:
            n_plain = 0
        return text[:n_plain] + ("*" * (length - n_plain))

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for vuln in data:
            message = vuln.get("message", "Unknown")
            key = vuln.get("key", "")
            value = vuln.get("value", "")
            file_path = vuln.get("file")
            line_raw = vuln.get("line")
            severity_raw = vuln.get("severity", "Info")

            line_number = None
            if line_raw is not None:
                try:
                    line_number = int(line_raw)
                except (ValueError, TypeError):
                    pass

            summary = f'Hardcoded {message} "{key}" in {file_path}:{line_raw}'
            masked_value = self._mask(str(value)) if value else ""
            description = f'{summary} `{masked_value}`'
            severity_str = self.SEVERITY_MAP.get(severity_raw, "info")

            findings.append(ParsedFinding(
                title=summary,
                severity=Severity.normalize(severity_str),
                tool="whispers",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=798,
                cve_id=None,
                cvss_score=None,
                recommendation=(
                    "Replace hardcoded secret with a placeholder (ie: ENV-VAR). "
                    "Invalidate the leaked secret and generate a new one."
                ),
                references=["https://cwe.mitre.org/data/definitions/798.html"],
                raw_data=vuln,
            ))
        return findings
