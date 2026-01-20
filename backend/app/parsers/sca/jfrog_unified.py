import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class JFrogUnifiedParser(BaseParser):
    name = "jfrog_unified"
    display_name = "JFrog Xray Unified"
    category = ScannerCategory.SCA
    file_types = ['json']
    description = "JFrog Xray unified vulnerability report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, (dict, list))
        except:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get("results", data.get("vulnerabilities", data.get("findings", [])))
            if not isinstance(items, list):
                items = [data]
            for item in items:
                if not isinstance(item, dict):
                    continue
                title = item.get("title", item.get("name", item.get("rule_id", item.get("id", "JFrog Xray Unified Finding"))))
                severity = item.get("severity", item.get("level", item.get("risk", "medium")))
                findings.append(ParsedFinding(
                    title=str(title),
                    severity=Severity.normalize(str(severity)),
                    tool=self.name,
                    description=item.get("description", item.get("message", "")),
                    asset=item.get("file", item.get("path", item.get("target", item.get("host", "unknown")))),
                    file_path=item.get("file", item.get("path")),
                    line_number=item.get("line", item.get("line_number")),
                    cve_id=item.get("cve", item.get("cve_id")),
                    raw_data=item,
                ))
        except json.JSONDecodeError:
            pass
        return findings
