import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class RustyHogParser(BaseParser):
    name = "rusty_hog"
    display_name = "RustyHog"
    category = ScannerCategory.SECRETS
    file_types = ["json"]
    description = "RustyHog secrets scanner (Choctaw, Duroc, Gottingen, Essex variants)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            # All RustyHog variants have 'reason' and 'stringsFound'
            return "reason" in first and "stringsFound" in first
        except Exception:
            return False

    def _detect_scanner(self, items: list) -> str:
        for item in items:
            if "commitHash" in item or "parent_commit_hash" in item:
                return "Choctaw Hog"
            if "linenum" in item or "diff" in item:
                return "Duroc Hog"
            if "issue_id" in item or "location" in item:
                return "Gottingen Hog"
            if "page_id" in item:
                return "Essex Hog"
        return "Rusty Hog"

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        scanner = self._detect_scanner(data)

        for vuln in data:
            reason = vuln.get("reason", "Unknown secret")
            strings_found = str(vuln.get("stringsFound") or "")
            file_path = vuln.get("path")
            date = vuln.get("date")

            description = f"\n**Reason:** {reason}"
            description += f"\n**This string was found:** {strings_found}"

            if scanner == "Choctaw Hog":
                commit_msg = vuln.get("commit", "")
                commit_hash = vuln.get("commitHash", "")
                parent_hash = vuln.get("parent_commit_hash")
                old_line = vuln.get("old_line_num")
                new_line = vuln.get("new_line_num")
                old_file_id = vuln.get("old_file_id")
                new_file_id = vuln.get("new_file_id")

                if commit_msg:
                    description += f"\n**Commit message:** {commit_msg}"
                if commit_hash:
                    description += f"\n**Commit hash:** {commit_hash}"
                if parent_hash:
                    description += f"\n**Parent commit hash:** {parent_hash}"
                if old_file_id and new_file_id:
                    description += f"\n**Old and new file IDs:** {old_file_id} - {new_file_id}"

                title = f"{reason} found in Git path {file_path} ({commit_hash})"
                line_number = int(new_line) if new_line is not None else None
                recommendation = "Please ensure no secret material nor confidential information is kept in clear within git repositories."

            elif scanner == "Duroc Hog":
                linenum = vuln.get("linenum")
                diff = vuln.get("diff")
                if linenum:
                    description += f"\n**Linenum of Issue:** {linenum}"
                if diff:
                    description += f"\n**Diff:** {diff}"
                title = f"{reason} found in path {file_path}"
                line_number = int(linenum) if linenum is not None else None
                recommendation = "Please ensure no secret material nor confidential information is kept in clear within directories, files, and archives."

            elif scanner == "Gottingen Hog":
                issue_id = vuln.get("issue_id", "")
                location = vuln.get("location", "")
                url = vuln.get("url", "")
                if issue_id:
                    description += f"\n**JIRA Issue ID:** {issue_id}"
                if location:
                    description += f"\n**JIRA location:** {location}"
                if url:
                    description += f"\n**JIRA url:** [{url}]({url})"
                title = f"{reason} found in Jira ID {issue_id} ({location})"
                if not file_path:
                    file_path = url
                line_number = None
                recommendation = "Please ensure no secret material nor confidential information is kept in clear within JIRA Tickets."

            elif scanner == "Essex Hog":
                page_id = vuln.get("page_id", "")
                url = vuln.get("url", "")
                if url:
                    description += f"\n**Confluence URL:** [{url}]({url})"
                if page_id:
                    description += f"\n**Confluence Page ID:** {page_id}"
                title = f"{reason} found in Confluence Page ID {page_id}"
                if not file_path:
                    file_path = url
                line_number = None
                recommendation = "Please ensure no secret material nor confidential information is kept in clear within Confluence Pages."

            else:
                # Generic fallback
                title = f"{reason} found"
                line_number = None
                recommendation = "Remove secrets from the repository."

            if date:
                description += f"\n**Date:** {date}"

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.HIGH,
                tool="rusty_hog",
                description=description.strip(),
                asset=file_path or "unknown",
                file_path=file_path or None,
                line_number=line_number,
                cwe_id=200,
                cve_id=None,
                cvss_score=None,
                recommendation=recommendation,
                raw_data=vuln,
            ))
        return findings
