import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TruffleHog3Parser(BaseParser):
    name = "trufflehog3"
    display_name = "TruffleHog3"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "TruffleHog v3 fork (truffleHog3) secrets scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            # trufflehog3 has either 'reason' (legacy) or 'rule' (current format)
            return "reason" in first or "rule" in first
        except Exception:
            return False

    def _severity_legacy(self, reason: str) -> Severity:
        if reason == "High Entropy":
            return Severity.INFO
        if any(kw in reason for kw in ("Oauth", "AWS", "Heroku")):
            return Severity.CRITICAL
        if reason == "Generic Secret":
            return Severity.MEDIUM
        return Severity.HIGH

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        seen = set()

        for obj in data:
            if "reason" in obj:
                finding = self._parse_legacy(obj, seen)
            elif "rule" in obj:
                finding = self._parse_current(obj, seen)
            else:
                continue

            if finding:
                findings.append(finding)

        return findings

    def _parse_legacy(self, obj: dict, seen: set) -> Optional[ParsedFinding]:
        file_path = obj.get("path", "")
        reason = obj.get("reason", "Unknown")
        commit = obj.get("commit", "")
        commit_hash = obj.get("commitHash", "")
        date = obj.get("date", "")
        branch = obj.get("branch", "")
        strings_found = obj.get("stringsFound", [])

        title = f"Hard Coded {reason} in: {file_path}"
        description = f"**Commit:** {str(commit).split(chr(10))[0]}\n"
        description += f"**Commit Hash:** {commit_hash}\n"
        description += f"**Commit Date:** {date}\n"
        description += f"**Branch:** {branch}\n"
        description += f"**Reason:** {reason}\n"
        description += f"**Path:** {file_path}\n"
        description += "\n**Strings Found:**\n```\n" + "\n".join(strings_found) + "\n```\n"

        severity = self._severity_legacy(reason)
        key = f"{file_path}|{reason}"
        if key in seen:
            return None
        seen.add(key)

        return ParsedFinding(
            title=title,
            severity=severity,
            tool="trufflehog3",
            description=description,
            asset=file_path or "unknown",
            file_path=file_path or None,
            line_number=0,
            cwe_id=798,
            cve_id=None,
            cvss_score=None,
            recommendation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
            raw_data=obj,
        )

    def _parse_current(self, obj: dict, seen: set) -> Optional[ParsedFinding]:
        rule = obj.get("rule", {})
        message = rule.get("message", "Unknown")
        severity_str = rule.get("severity", "High")
        if severity_str:
            severity_str = severity_str.capitalize()

        file_path = obj.get("path")
        line = obj.get("line", 0)
        try:
            line = int(line)
        except (ValueError, TypeError):
            line = 0

        secret = obj.get("secret", "")
        context = obj.get("context")
        branch = obj.get("branch")
        commit_msg = obj.get("message")
        commit = obj.get("commit")
        date = obj.get("date")

        title = f"{message} found in {file_path}"
        description = f"**Secret:** {secret}\n"
        if context:
            description += "**Context:**\n"
            for k, v in context.items():
                description += f"    {k}: {v}\n"
        if branch:
            description += f"**Branch:** {branch}\n"
        if commit_msg:
            description += f"**Commit message:** {commit_msg}\n"
        if commit:
            description += f"**Commit hash:** {commit}\n"
        if date:
            description += f"**Commit date:** {date}\n"

        key = f"{title}|{secret}|{severity_str}|{line}"
        if key in seen:
            return None
        seen.add(key)

        return ParsedFinding(
            title=title,
            severity=Severity.normalize(severity_str),
            tool="trufflehog3",
            description=description.replace("\x00", "�"),
            asset=file_path or "unknown",
            file_path=file_path,
            line_number=line,
            cwe_id=798,
            cve_id=None,
            cvss_score=None,
            recommendation="Secrets and passwords should be stored in a secure vault or secure storage.",
            raw_data=obj,
        )
