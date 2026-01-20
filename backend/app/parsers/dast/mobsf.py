import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class MobSFParser(BaseParser):
    name = "mobsf"
    display_name = "MobSF"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Mobile Security Framework for Android/iOS security analysis"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "appsec" in data or "code_analysis" in data or "binary_analysis" in data or "file_name" in data and "md5" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            app_name = data.get("file_name", data.get("app_name", "Mobile App"))
            for section in ["code_analysis", "binary_analysis", "appsec"]:
                section_data = data.get(section, {})
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        if isinstance(value, dict):
                            findings.append(ParsedFinding(
                                title=value.get("title", key),
                                description=value.get("description", str(value.get("metadata", ""))),
                                severity=self._map_severity(value.get("severity", value.get("level", "medium"))),
                                tool=self.name,
                                asset=app_name,
                                cwe=value.get("cwe"),
                                raw_data=value
                            ))
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict):
                                    findings.append(ParsedFinding(
                                        title=item.get("title", key),
                                        description=item.get("description", ""),
                                        severity=self._map_severity(item.get("severity", "medium")),
                                        tool=self.name,
                                        asset=app_name,
                                        raw_data=item
                                    ))
            for finding in data.get("findings", []):
                findings.append(ParsedFinding(
                    title=finding.get("title", "MobSF Finding"),
                    description=finding.get("description", ""),
                    severity=self._map_severity(finding.get("severity", "medium")),
                    tool=self.name,
                    asset=app_name,
                    raw_data=finding
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {
            "critical": "critical", "high": "high", "warning": "medium", "medium": "medium",
            "low": "low", "info": "info", "good": "info", "secure": "info"
        }
        return mapping.get(str(sev).lower(), "medium")
