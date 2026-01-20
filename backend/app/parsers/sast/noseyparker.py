import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class NoseyParkerParser(BaseParser):
    name = "noseyparker"
    display_name = "Nosey Parker"
    category = ScannerCategory.SAST
    file_types = ["json", "jsonl"]
    description = "Praetorian Nosey Parker secrets scanner"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content.split("\n")[0] if "\n" in content else content)
            return "rule_name" in data or "matches" in data and "provenance" in str(data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            lines = content.strip().split("\n")
            for line in lines:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    matches = data.get("matches", [data])
                    for match in matches:
                        findings.append(ParsedFinding(
                            title=f"Secret Found: {match.get('rule_name', data.get('rule_name', 'Unknown'))}",
                            description=match.get("snippet", match.get("match_content", "")),
                            severity="high",
                            tool=self.name,
                            asset=match.get("provenance", {}).get("path", match.get("path", "unknown")),
                            raw_data=match
                        ))
                except:
                    continue
        except:
            pass
        return findings
