import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class AndrobugsParser(BaseParser):
    name = "androbugs"
    display_name = "AndroBugs"
    category = ScannerCategory.MOBILE
    file_types = ["json", "txt"]
    description = "AndroBugs Framework for Android vulnerability scanning"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "androbugs" in str(data).lower() or "analyze_result" in data
        except:
            return "AndroBugs" in content or "[Critical]" in content or "[Warning]" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                for category, issues in data.get("analyze_result", data).items():
                    if isinstance(issues, list):
                        for issue in issues:
                            findings.append(ParsedFinding(
                                title=issue.get("title", category),
                                description=issue.get("description", str(issue)),
                                severity=self._map_severity(issue.get("severity", "medium")),
                                tool=self.name,
                                asset=data.get("apk_name", "Android App"),
                                raw_data=issue
                            ))
            else:
                current_severity = "medium"
                for line in content.split("\n"):
                    line = line.strip()
                    if "[Critical]" in line:
                        current_severity = "critical"
                    elif "[Warning]" in line:
                        current_severity = "high"
                    elif "[Notice]" in line:
                        current_severity = "medium"
                    elif "[Info]" in line:
                        current_severity = "info"
                    elif line and not line.startswith("-") and not line.startswith("="):
                        if any(x in line for x in ["vulnerability", "issue", "found", "detected"]):
                            findings.append(ParsedFinding(
                                title=line[:100],
                                description=line,
                                severity=current_severity,
                                tool=self.name,
                                asset="Android App",
                                raw_data={"line": line}
                            ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "warning": "high", "medium": "medium", "notice": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")
