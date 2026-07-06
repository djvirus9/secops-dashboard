import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

# SonarQube severity mapping
_SQ_SEVERITY = {
    "blocker": "critical",
    "critical": "high",
    "major": "medium",
    "minor": "low",
    "info": "info",
}

# SonarQube type mapping to tags
_SQ_TYPE = {
    "BUG": "bug",
    "VULNERABILITY": "vulnerability",
    "CODE_SMELL": "code-smell",
    "SECURITY_HOTSPOT": "security-hotspot",
}


@ParserRegistry.register
class ApiSonarQubeParser(BaseParser):
    name = "api_sonarqube"
    display_name = "SonarQube API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "SonarQube API JSON export (issues)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # Standard SonarQube API response has "issues" key
                if "issues" in data:
                    issues = data["issues"]
                    if isinstance(issues, list) and issues:
                        first = issues[0]
                        return isinstance(first, dict) and "rule" in first and "component" in first
                # Also accept hotspots format
                if "hotspots" in data:
                    return True
            return False
        except Exception:
            return False

    def _parse_issue(self, issue: dict) -> Optional[ParsedFinding]:
        rule = issue.get("rule", "")
        message = issue.get("message", "Unknown Issue")
        severity = issue.get("severity", "info")
        issue_type = issue.get("type", "")
        component = issue.get("component", "unknown")
        line = issue.get("line")
        status = issue.get("status", "")
        resolution = issue.get("resolution", "")

        sev_str = _SQ_SEVERITY.get((severity or "").lower(), "info")
        title = f"[{rule}] {message}"
        if len(title) > 500:
            title = title[:497] + "..."

        description_lines = [
            f"**Rule**: {rule}",
            f"**Message**: {message}",
            f"**Component**: {component}",
            f"**Status**: {status}",
        ]
        if resolution:
            description_lines.append(f"**Resolution**: {resolution}")
        if issue.get("effort"):
            description_lines.append(f"**Effort**: {issue['effort']}")
        description = "\n".join(description_lines)

        tags = []
        for t in issue.get("tags", []):
            tags.append(t)
        if issue_type and issue_type in _SQ_TYPE:
            tags.append(_SQ_TYPE[issue_type])

        cwe_id = None
        for tag in issue.get("tags", []):
            if tag.lower().startswith("cwe-"):
                try:
                    cwe_id = int(tag[4:])
                    break
                except ValueError:
                    pass

        return ParsedFinding(
            title=title,
            severity=Severity.normalize(sev_str),
            tool=self.name,
            description=description,
            asset=component,
            file_path=component if "/" in component else None,
            line_number=int(line) if line else None,
            cwe_id=cwe_id,
            tags=tags,
            raw_data=issue,
        )

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for issue in data.get("issues", []):
                f = self._parse_issue(issue)
                if f:
                    findings.append(f)
            for hotspot in data.get("hotspots", []):
                # Hotspots use different field names
                rule_key = hotspot.get("ruleKey", hotspot.get("rule", ""))
                message = hotspot.get("message", hotspot.get("summary", "Security Hotspot"))
                component = hotspot.get("component", "unknown")
                line = hotspot.get("line")
                vuln_prob = hotspot.get("vulnerabilityProbability", "medium")
                sev_map = {"high": "high", "medium": "medium", "low": "low"}
                sev_str = sev_map.get(vuln_prob.lower(), "medium")
                findings.append(ParsedFinding(
                    title=f"[{rule_key}] {message}",
                    severity=Severity.normalize(sev_str),
                    tool=self.name,
                    description=f"**Rule**: {rule_key}\n**Component**: {component}\n**Message**: {message}",
                    asset=component,
                    line_number=int(line) if line else None,
                    tags=["security-hotspot"],
                    raw_data=hotspot,
                ))
        except Exception:
            pass
        return findings
