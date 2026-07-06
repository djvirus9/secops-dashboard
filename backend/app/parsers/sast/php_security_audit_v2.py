import json
import math
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PhpSecurityAuditV2Parser(BaseParser):
    name = "php_security_audit_v2"
    display_name = "PHP Security Audit v2"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "PHP Security Audit v2 static analysis tool"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                "files" in data
                and isinstance(data["files"], dict)
                and any(
                    "messages" in v
                    for v in data["files"].values()
                    if isinstance(v, dict)
                )
            )
        except Exception:
            return False

    @staticmethod
    def _get_severity(severity_int: int) -> str:
        sev = math.ceil(severity_int / 2)
        if sev == 5:
            return "critical"
        if sev == 4:
            return "high"
        if sev == 3:
            return "medium"
        return "low"

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for filepath, report in data.get("files", {}).items():
            errors = report.get("errors") or 0
            warns = report.get("warnings") or 0
            if errors + warns == 0:
                continue

            for issue in report.get("messages", []):
                source = issue.get("source", "Unknown")
                message = issue.get("message", "")
                line = issue.get("line")
                column = issue.get("column")
                severity_int = issue.get("severity", 2)

                description = f"Filename: {filepath}\n"
                description += f"Line: {line}\n"
                description += f"Column: {column}\n"
                description += f"Rule Source: {source}\n"
                description += f"Details: {message}\n"

                severity_str = self._get_severity(severity_int)

                line_number = None
                if line is not None:
                    try:
                        line_number = int(line)
                    except (ValueError, TypeError):
                        pass

                findings.append(ParsedFinding(
                    title=source,
                    severity=Severity.normalize(severity_str),
                    tool="php_security_audit_v2",
                    description=description,
                    asset=filepath,
                    file_path=filepath,
                    line_number=line_number,
                    cwe_id=None,
                    cve_id=None,
                    cvss_score=None,
                    recommendation="",
                    raw_data=issue,
                ))
        return findings
