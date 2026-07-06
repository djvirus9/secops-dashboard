import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _parse_rule_matches(rule_matches) -> List[dict]:
    results = []
    for rule_match in rule_matches or []:
        rule = rule_match.get("rule", {})
        rule_id = rule.get("id", "N/A")
        rule_name = rule.get("name", "N/A")
        severity = rule_match.get("severity", "low")
        for match in rule_match.get("matches", []):
            resource_name = match.get("resourceName", "N/A")
            file_name = match.get("fileName", "N/A")
            line_number = match.get("lineNumber")
            match_content = match.get("matchContent", "N/A")
            expected = match.get("expected", "N/A")
            found = match.get("found", "N/A")
            description = (
                f"**Rule ID**: {rule_id}\n"
                f"**Rule Name**: {rule_name}\n"
                f"**Resource Name**: {resource_name}\n"
                f"**File Name**: {file_name}\n"
                f"**Line Number**: {line_number}\n"
                f"**Match Content**: {match_content}\n"
                f"**Expected**: {expected}\n"
                f"**Found**: {found}\n"
            )
            results.append({
                "title": f"{rule_name} - {resource_name}",
                "severity": severity,
                "description": description,
                "file_path": file_name,
                "asset": file_name,
                "line_number": line_number,
                "raw": match,
            })
    return results


def _parse_secrets(secrets) -> List[dict]:
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
class WizCLIIaCParser(BaseParser):
    name = "wizcli_iac"
    display_name = "Wiz CLI IaC Scan"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "Wiz CLI Infrastructure-as-Code (IaC) scan"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            result = data.get("result", {})
            return "ruleMatches" in result
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data.get("result", {})

            for item in _parse_rule_matches(results.get("ruleMatches")):
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
