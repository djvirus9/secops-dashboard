import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class DetectSecretsParser(BaseParser):
    name = "detect_secrets"
    display_name = "Detect-secrets"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Yelp's detect-secrets for finding secrets in code"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "results" in data and "generated_at" in data or "version" in data and "results" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("results", {})
            for file_path, secrets in results.items():
                for secret in secrets:
                    findings.append(ParsedFinding(
                        title=f"Secret Detected: {secret.get('type', 'Unknown Secret')}",
                        description=f"Potential secret found at line {secret.get('line_number', 'unknown')}",
                        severity="high",
                        tool=self.name,
                        asset=file_path,
                        raw_data={"file": file_path, **secret}
                    ))
        except:
            pass
        return findings
