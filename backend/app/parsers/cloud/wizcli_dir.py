import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _parse_libraries(libraries) -> List[dict]:
    """Extract findings from wizcli libraries section."""
    results = []
    for lib in libraries or []:
        lib_name = lib.get("name", "N/A")
        lib_version = lib.get("version", "N/A")
        lib_path = lib.get("path", "N/A")
        for vuln in lib.get("vulnerabilities", []):
            vuln_name = vuln.get("name", "N/A")
            severity = vuln.get("severity", "low")
            description = (
                f"**Library Name**: {lib_name}\n"
                f"**Library Version**: {lib_version}\n"
                f"**Library Path**: {lib_path}\n"
                f"**Vulnerability Name**: {vuln_name}\n"
                f"**Fixed Version**: {vuln.get('fixedVersion', 'N/A')}\n"
                f"**Description**: {vuln.get('description', 'N/A')}\n"
            )
            results.append({
                "title": f"{lib_name} - {vuln_name}",
                "severity": severity,
                "description": description,
                "file_path": lib_path,
                "asset": lib_path,
                "raw": vuln,
            })
    return results


def _parse_secrets(secrets) -> List[dict]:
    """Extract findings from wizcli secrets section."""
    results = []
    for secret in secrets or []:
        desc_text = secret.get("description", "N/A")
        file_name = secret.get("path", "N/A")
        line_number = secret.get("lineNumber")
        secret_type = secret.get("type", "N/A")
        description = (
            f"**Description**: {desc_text}\n"
            f"**File Name**: {file_name}\n"
            f"**Line Number**: {line_number}\n"
            f"**Type**: {secret_type}\n"
        )
        results.append({
            "title": f"Secret: {desc_text}",
            "severity": "high",
            "description": description,
            "file_path": file_name,
            "asset": file_name,
            "line_number": line_number,
            "raw": secret,
        })
    return results


@ParserRegistry.register
class WizCLIDirParser(BaseParser):
    name = "wizcli_dir"
    display_name = "Wiz CLI Directory Scan"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "Wiz CLI directory scan for libraries and secrets"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            result = data.get("result", {})
            return "libraries" in result or ("secrets" in result and "ruleMatches" not in result and "osPackages" not in result)
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("result", {})

            for item in _parse_libraries(results.get("libraries")):
                findings.append(ParsedFinding(
                    title=item["title"],
                    severity=Severity.normalize(item["severity"]),
                    tool=self.name,
                    description=item["description"],
                    asset=item["asset"],
                    file_path=item["file_path"],
                    raw_data=item["raw"],
                ))

            for item in _parse_secrets(results.get("secrets")):
                findings.append(ParsedFinding(
                    title=item["title"],
                    severity=Severity.normalize(item["severity"]),
                    tool=self.name,
                    description=item["description"],
                    asset=item["asset"],
                    file_path=item["file_path"],
                    line_number=item.get("line_number"),
                    raw_data=item["raw"],
                ))
        except Exception:
            pass
        return findings
