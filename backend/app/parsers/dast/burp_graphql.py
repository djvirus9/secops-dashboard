import json
import re
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class BurpGraphQLParser(BaseParser):
    name = "burp_graphql"
    display_name = "Burp GraphQL API"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Burp Suite DAST findings from the GraphQL API"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "Issues" in data
        except Exception:
            return False

    @staticmethod
    def _strip_html(html_str: str) -> str:
        """Remove HTML tags and unescape basic HTML entities."""
        text = re.sub(r"<[^>]+>", " ", html_str)
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'")
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _extract_cwe(html_str: str) -> Optional[int]:
        match = re.search(r"CWE-(\d+)", html_str, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        issues = data.get("Issues", [])

        # Group by issue name to deduplicate
        issue_dict: dict = {}

        for issue in issues:
            issue_type = issue.get("issue_type", {})
            issue_name = issue_type.get("name", "Unknown")
            origin = issue.get("origin", "")
            path = issue.get("path", "")
            url = origin + path

            severity_str = issue.get("severity", "info")

            if issue_name not in issue_dict:
                description = ""
                if issue.get("description_html"):
                    description += self._strip_html(issue["description_html"]) + "\n\n"
                if issue_type.get("description_html"):
                    description += "**Background:** " + self._strip_html(issue_type["description_html"])

                mitigation = ""
                if issue.get("remediation_html"):
                    mitigation += self._strip_html(issue["remediation_html"]) + "\n"
                if issue_type.get("remediation_html"):
                    mitigation += self._strip_html(issue_type["remediation_html"])

                references_text = ""
                cwe_id = None
                if issue_type.get("vulnerability_classifications_html"):
                    cwe_id = self._extract_cwe(issue_type["vulnerability_classifications_html"])
                    references_text = self._strip_html(issue_type.get("vulnerability_classifications_html", ""))
                if issue_type.get("references_html"):
                    references_text += "\n" + self._strip_html(issue_type["references_html"])

                issue_dict[issue_name] = {
                    "title": issue_name,
                    "severity": severity_str,
                    "description": description.strip(),
                    "mitigation": mitigation.strip(),
                    "cwe_id": cwe_id,
                    "references": [references_text] if references_text else [],
                    "assets": [url],
                    "raw": issue,
                }
            else:
                if url not in issue_dict[issue_name]["assets"]:
                    issue_dict[issue_name]["assets"].append(url)

        for info in issue_dict.values():
            assets = info["assets"]
            asset = assets[0] if assets else "unknown"

            findings.append(ParsedFinding(
                title=info["title"],
                severity=Severity.normalize(info["severity"]),
                tool="burp_graphql",
                description=info["description"],
                asset=asset,
                cwe_id=info["cwe_id"],
                cve_id=None,
                cvss_score=None,
                recommendation=info["mitigation"],
                references=info["references"],
                raw_data=info["raw"],
            ))

        return findings
