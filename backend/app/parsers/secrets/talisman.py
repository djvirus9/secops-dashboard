import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TalismanParser(BaseParser):
    name = "talisman"
    display_name = "Talisman"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "Talisman git hook secrets scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            results = data.get("results")
            if not isinstance(results, list):
                return False
            if not results:
                return True
            first = results[0]
            return "filename" in first and "failure_list" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        results = data.get("results", [])

        seen = set()

        for result in results:
            file_path = result.get("filename", "")
            for issue in result.get("failure_list", []):
                commits = issue.get("commits", [])
                if not commits:
                    continue

                message = issue.get("message", "")
                severity_raw = issue.get("severity", "Medium")
                severity_str = severity_raw.capitalize() if severity_raw else "Medium"

                title = f"Secret pattern found in {file_path} file"
                description = ""
                if file_path:
                    description += f"**File path:** {file_path}\n"
                if severity_raw:
                    description += f"**Severity:** {severity_raw}\n"
                if message:
                    description += f"**Message:** {message}\n"
                if commits:
                    description += f"**Commit hash:** {commits}\n"

                key = f"{title}|{message}|{file_path}|{severity_str}"
                if key in seen:
                    continue
                seen.add(key)

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity_str),
                    tool="talisman",
                    description=description,
                    asset=file_path or "unknown",
                    file_path=file_path or None,
                    line_number=None,
                    cwe_id=798,
                    cve_id=None,
                    cvss_score=None,
                    recommendation="Remove secrets from git history and rotate exposed credentials.",
                    raw_data=issue,
                ))
        return findings
