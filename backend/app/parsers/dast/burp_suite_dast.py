import re
from html.parser import HTMLParser
from typing import List, Optional, Dict

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


class _BurpHTMLParser(HTMLParser):
    """
    Simple state-machine HTML parser for Burp Suite DAST HTML reports.
    Extracts issue titles and severities from the summary table, then
    descriptions/mitigations from the detail sections.
    """

    def __init__(self):
        super().__init__()
        self._findings: Dict[str, dict] = {}
        self._current_text = []
        self._in_issue_table = False
        self._in_detail_section = False
        self._current_issue_name: Optional[str] = None
        self._current_header: Optional[str] = None
        self._in_h2 = False
        self._in_h3 = False
        self._in_h1 = False
        self._depth = 0
        self._base_host: Optional[str] = None

    def _flush_text(self) -> str:
        text = " ".join(self._current_text).strip()
        text = re.sub(r"\s+", " ", text)
        self._current_text = []
        return text

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        classes = attrs_dict.get("class", "")

        if tag in ("h1", "h2", "h3"):
            self._current_text = []

        if tag == "h1":
            self._in_h1 = True
        elif tag == "h2":
            self._in_h2 = True
        elif tag == "h3":
            self._in_h3 = True
        elif tag == "td":
            self._current_text = []

    def handle_endtag(self, tag):
        if tag == "h1":
            self._in_h1 = False
            text = self._flush_text()
            if "Issues found on" in text:
                self._base_host = text.replace("Issues found on", "").strip().rstrip("/")

        elif tag == "h2":
            self._in_h2 = False
            text = self._flush_text()
            if text:
                self._current_issue_name = text
                if text not in self._findings:
                    self._findings[text] = {
                        "title": text,
                        "severity": "info",
                        "description": "",
                        "mitigation": "",
                        "cwe_id": None,
                        "references": [],
                        "urls": [],
                    }

        elif tag == "h3":
            self._in_h3 = False
            self._current_header = self._flush_text().lower().rstrip(":")

        elif tag == "td":
            text = self._flush_text()
            # Used by table rows to capture severity
            if text and self._current_issue_name:
                sev_lower = text.lower()
                if sev_lower in ("critical", "high", "medium", "low", "info", "information"):
                    if self._current_issue_name in self._findings:
                        self._findings[self._current_issue_name]["severity"] = sev_lower

        elif tag == "div":
            if self._current_header and self._current_issue_name:
                text = self._flush_text()
                info = self._findings.get(self._current_issue_name)
                if info and text:
                    h = self._current_header
                    if h in ("issue detail", "issue description", "issue background"):
                        info["description"] += text + "\n"
                    elif h in ("remediation detail", "remediation background"):
                        info["mitigation"] += text + "\n"
                    elif h in ("vulnerability classifications", "references"):
                        cwe_m = re.search(r"CWE-(\d+)", text, re.IGNORECASE)
                        if cwe_m and info["cwe_id"] is None:
                            info["cwe_id"] = int(cwe_m.group(1))
                        info["references"].append(text)
                self._current_header = None

    def handle_data(self, data):
        text = data.strip()
        if text:
            self._current_text.append(text)

    def get_findings(self) -> Dict[str, dict]:
        return self._findings


@ParserRegistry.register
class BurpSuiteDASTParser(BaseParser):
    name = "burp_suite_dast"
    display_name = "Burp Suite DAST"
    category = ScannerCategory.DAST
    file_types = ["html", "htm"]
    description = "Burp Suite DAST HTML scan report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        if filename and filename.lower().endswith((".html", ".htm")):
            return "burpsuite" in content.lower() or "burp suite" in content.lower() or "issue-container" in content.lower()
        try:
            stripped = content.strip().lower()
            return (
                stripped.startswith("<!doctype html") or stripped.startswith("<html")
            ) and ("burp" in stripped or "issue-container" in stripped)
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        parser = _BurpHTMLParser()
        parser.feed(content)

        for info in parser.get_findings().values():
            title = info["title"]
            if not title:
                continue

            # Determine the best asset URL
            asset = "unknown"
            if parser._base_host:
                asset = parser._base_host

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(info["severity"]),
                tool="burp_suite_dast",
                description=info["description"].strip(),
                asset=asset,
                cwe_id=info["cwe_id"],
                cve_id=None,
                cvss_score=None,
                recommendation=info["mitigation"].strip(),
                references=info["references"],
                raw_data=info,
            ))

        return findings
