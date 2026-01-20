import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CodeQLParser(BaseParser):
    name = "codeql"
    display_name = "CodeQL / GitHub Advanced Security"
    category = ScannerCategory.SAST
    file_types = ["json", "sarif"]
    description = "GitHub's semantic code analysis engine"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if "$schema" in data and "sarif" in str(data.get("$schema", "")):
                return True
            if "runs" in data and isinstance(data["runs"], list):
                return True
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for run in data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "codeql")
            rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_info = rules.get(rule_id, {})
                
                level = result.get("level", "warning")
                if level == "error":
                    severity = Severity.HIGH
                elif level == "warning":
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                
                locations = result.get("locations", [])
                file_path = None
                line_number = None
                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    file_path = physical.get("artifactLocation", {}).get("uri")
                    line_number = physical.get("region", {}).get("startLine")
                
                cwe_id = None
                tags = rule_info.get("properties", {}).get("tags", [])
                for tag in tags:
                    if tag.startswith("external/cwe/cwe-"):
                        try:
                            cwe_id = int(tag.split("cwe-")[1])
                        except:
                            pass
                        break
                
                finding = ParsedFinding(
                    title=rule_info.get("shortDescription", {}).get("text", rule_id),
                    severity=severity,
                    tool=tool_name.lower().replace(" ", "-"),
                    description=result.get("message", {}).get("text", ""),
                    asset=file_path or "unknown",
                    file_path=file_path,
                    line_number=line_number,
                    cwe_id=cwe_id,
                    references=rule_info.get("helpUri", []) if isinstance(rule_info.get("helpUri"), list) else [rule_info.get("helpUri")] if rule_info.get("helpUri") else [],
                    tags=tags,
                    raw_data=result,
                )
                findings.append(finding)
        
        return findings
