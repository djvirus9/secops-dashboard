import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class TruffleHogParser(BaseParser):
    name = "trufflehog"
    display_name = "TruffleHog"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "TruffleHog secrets scanner (supports v2 and v3 JSON output)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            lines = content.strip().splitlines()
            if not lines:
                return False
            first_line = lines[0].strip()
            first_obj = json.loads(first_line)
            # v2: has 'path' and 'reason'
            # v3: has 'SourceMetadata' and 'DetectorName'
            return "SourceMetadata" in first_obj or ("path" in first_obj and "reason" in first_obj)
        except Exception:
            return False

    def _detect_version(self, first_obj: dict) -> str:
        if "SourceMetadata" in first_obj:
            return "v3"
        return "v2"

    def _severity_v2(self, reason: str) -> Severity:
        if reason == "High Entropy":
            return Severity.INFO
        if any(kw in reason for kw in ("Oauth", "AWS", "Heroku")):
            return Severity.CRITICAL
        if reason == "Generic Secret":
            return Severity.MEDIUM
        return Severity.HIGH

    def _severity_v3(self, detector_name: str, verified: bool) -> Severity:
        if verified:
            return Severity.CRITICAL
        if any(kw in detector_name for kw in ("Oauth", "AWS", "Heroku")):
            return Severity.CRITICAL
        if detector_name == "PrivateKey":
            return Severity.HIGH
        if detector_name == "Generic Secret":
            return Severity.MEDIUM
        return Severity.CRITICAL

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        lines = content.strip().splitlines()
        if not lines:
            return findings

        try:
            first_obj = json.loads(lines[0])
        except (json.JSONDecodeError, IndexError):
            return findings

        version = self._detect_version(first_obj)

        if version == "v3":
            return self._parse_v3(lines)
        return self._parse_v2(lines)

    def _parse_v2(self, lines: list) -> List[ParsedFinding]:
        findings = []
        seen = set()

        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            file_path = obj.get("path")
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
            description += "\n**Strings Found:**\n```" + "\n".join(strings_found) + "```\n"

            severity = self._severity_v2(reason)
            key = f"{file_path}|{reason}"

            if key in seen:
                continue
            seen.add(key)

            findings.append(ParsedFinding(
                title=title,
                severity=severity,
                tool="trufflehog",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=0,
                cwe_id=798,
                cve_id=None,
                cvss_score=None,
                recommendation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                raw_data=obj,
            ))
        return findings

    def _parse_v3(self, lines: list) -> List[ParsedFinding]:
        findings = []
        seen = set()

        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            metadata = obj.get("SourceMetadata", {}).get("Data", {})
            source_data = {}
            if metadata:
                source_key = list(metadata.keys())[0]
                source_data = metadata.get(source_key, {})

            file_path = source_data.get("file", "")
            email = source_data.get("email", "")
            commit = source_data.get("commit", "")
            detector_name = obj.get("DetectorName", "")
            date = source_data.get("timestamp", "")
            line_number = source_data.get("line", 0)
            repository = source_data.get("repository", "")
            link = source_data.get("link", "")
            redacted = obj.get("Redacted", "")
            verified = bool(obj.get("Verified", False))
            raw = obj.get("Raw", "")
            rawV2 = obj.get("RawV2", "")

            title = f"Hard Coded {detector_name} secret in: {file_path}"
            description = f"**Repository:** {repository}\n"
            description += f"**Link:** {link}\n"
            description += f"**Commit Hash:** {commit}\n"
            description += f"**Commit Date:** {date}\n"
            description += f"**Committer:** {email}\n"
            description += f"**Reason:** {detector_name}\n"
            description += f"**Path:** {file_path}\n"
            description += f"**Contents:** {redacted}\n"

            severity = self._severity_v3(detector_name, verified)
            key = f"{file_path}|{detector_name}|{line_number}|{commit}|{raw}{rawV2}"

            if key in seen:
                continue
            seen.add(key)

            recommendation = "Secrets and passwords should be stored in a secure vault and/or secure storage."
            if link:
                recommendation += f"\nSee the commit here: {link}"

            findings.append(ParsedFinding(
                title=title,
                severity=severity,
                tool="trufflehog",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path or None,
                line_number=int(line_number) if line_number else 0,
                cwe_id=798,
                cve_id=None,
                cvss_score=None,
                recommendation=recommendation,
                raw_data=obj,
            ))
        return findings
