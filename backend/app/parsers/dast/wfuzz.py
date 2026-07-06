import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WFuzzParser(BaseParser):
    name = "wfuzz"
    display_name = "WFuzz"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "WFuzz web application fuzzer"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return isinstance(first, dict) and "url" in first and "code" in first
        except Exception:
            return False

    def _severity_from_code(self, code: Optional[int]) -> Severity:
        if code is None:
            return Severity.LOW
        if 200 <= code <= 299:
            return Severity.HIGH
        if 300 <= code <= 399:
            return Severity.LOW
        if 400 <= code <= 499:
            return Severity.MEDIUM
        if code >= 500:
            return Severity.LOW
        return Severity.LOW

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        seen = set()
        for item in data:
            url = item.get("url", "unknown")
            code = item.get("code")
            payload = item.get("payload", "")

            dedup_key = f"{url}:{code}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = self._severity_from_code(code)
            description = (
                f"The URL `{url}` was discovered during fuzzing.\n"
                f"HTTP response code: {code}\n"
                f"Payload: {payload}\n\n"
                "This URL should not be exposed. Please review your web server configuration."
            )

            findings.append(ParsedFinding(
                title=f"Found {url}",
                severity=severity,
                tool="wfuzz",
                description=description,
                asset=url,
                cwe_id=200,
                cve_id=None,
                cvss_score=None,
                recommendation="Review access controls and restrict unintended URL exposure.",
                raw_data=item,
            ))

        return findings
