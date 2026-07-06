import json
import re
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WhiteHatSentinelParser(BaseParser):
    name = "whitehat_sentinel"
    display_name = "WhiteHat Sentinel"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "WhiteHat Sentinel dynamic application security testing"

    SEVERITY_MAP = {
        0: "info",
        1: "info",
        2: "low",
        3: "medium",
        4: "high",
        5: "critical",
        6: "critical",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "collection" in data
        except Exception:
            return False

    def _strip_html(self, html_str: str) -> str:
        text = re.sub(r"<[^>]+>", " ", html_str)
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        return re.sub(r"\s+", " ", text).strip()

    def _parse_cwe(self, tags: list) -> Optional[int]:
        for tag in tags:
            if tag.startswith("CWE-"):
                try:
                    return int(tag.split("-")[1])
                except (IndexError, ValueError):
                    pass
        return None

    def _get_severity(self, risk_id) -> str:
        try:
            idx = int(risk_id)
            return self.SEVERITY_MAP.get(idx, "info")
        except (TypeError, ValueError):
            return "info"

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        collection = data.get("collection", [])
        if not collection:
            return findings

        for vuln in collection:
            vuln_class = vuln.get("class", "Unknown Vulnerability")
            vuln_id = vuln.get("id", "")
            site = vuln.get("site", "")
            status = vuln.get("status", "open")

            risk_id = vuln.get("custom_risk") or vuln.get("risk", 0)
            severity_str = self._get_severity(risk_id)

            # Parse description
            desc_node = vuln.get("description", {})
            description_html = desc_node.get("description", "")
            description = self._strip_html(description_html)

            # Parse solution
            solution_node = vuln.get("solution", {})
            solution_html = solution_node.get("solution", "")
            solution = self._strip_html(re.sub(r"<.+?>", " ", solution_html))

            # References
            references = []
            ref_match = re.findall(r'href="(https?://[^"]+)"', description_html + solution_html)
            references = list(set(ref_match))
            if vuln_id and site:
                references.append(
                    f"https://source.whitehatsec.com/asset-management/site-summary/{site}/findings/{vuln_id}"
                )

            # CWE from tags in attack vectors
            cwe_id = None
            attack_vectors = vuln.get("attack_vectors", [])
            asset = "unknown"
            if attack_vectors:
                first_av = attack_vectors[0]
                scanner_tags = first_av.get("scanner_tags", [])
                cwe_id = self._parse_cwe(scanner_tags)
                req = first_av.get("request", {})
                asset = req.get("url", "unknown")

            findings.append(ParsedFinding(
                title=vuln_class,
                severity=Severity.normalize(severity_str),
                tool="whitehat_sentinel",
                description=description,
                asset=asset,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation=solution,
                references=references,
                raw_data=vuln,
            ))

        return findings
