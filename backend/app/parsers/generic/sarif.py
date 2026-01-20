import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SARIFParser(BaseParser):
    name = "sarif"
    display_name = "SARIF"
    category = ScannerCategory.GENERIC
    file_types = ["sarif", "json"]
    description = "Static Analysis Results Interchange Format (SARIF)"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if "$schema" in data:
                return "sarif" in str(data["$schema"]).lower()
            return "runs" in data and "tool" in str(data)[:500]
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for run in data.get("runs", []):
            tool_info = run.get("tool", {}).get("driver", {})
            tool_name = tool_info.get("name", "sarif-tool").lower().replace(" ", "-")
            
            rules = {}
            for rule in tool_info.get("rules", []):
                rules[rule["id"]] = rule
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_info = rules.get(rule_id, {})
                
                level = result.get("level", rule_info.get("defaultConfiguration", {}).get("level", "warning"))
                severity_map = {
                    "error": Severity.HIGH,
                    "warning": Severity.MEDIUM,
                    "note": Severity.LOW,
                    "none": Severity.INFO,
                }
                
                locations = result.get("locations", [])
                file_path = None
                line_number = None
                asset = "unknown"
                
                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    file_path = artifact.get("uri", artifact.get("uriBaseId", ""))
                    asset = file_path or "unknown"
                    
                    region = physical.get("region", {})
                    line_number = region.get("startLine")
                
                short_desc = rule_info.get("shortDescription", {})
                if isinstance(short_desc, dict):
                    title = short_desc.get("text", rule_id)
                else:
                    title = str(short_desc) if short_desc else rule_id
                
                message = result.get("message", {})
                if isinstance(message, dict):
                    description = message.get("text", "")
                else:
                    description = str(message)
                
                cwe_id = None
                tags = rule_info.get("properties", {}).get("tags", [])
                for tag in tags:
                    if "cwe" in tag.lower():
                        try:
                            cwe_id = int(tag.split("-")[-1])
                        except:
                            pass
                        break
                
                finding = ParsedFinding(
                    title=title,
                    severity=severity_map.get(level, Severity.MEDIUM),
                    tool=tool_name,
                    description=description,
                    asset=asset,
                    file_path=file_path,
                    line_number=line_number,
                    cwe_id=cwe_id,
                    recommendation=rule_info.get("help", {}).get("text", "") if isinstance(rule_info.get("help"), dict) else "",
                    references=[rule_info.get("helpUri")] if rule_info.get("helpUri") else [],
                    tags=tags,
                    raw_data=result,
                )
                findings.append(finding)
        
        return findings
