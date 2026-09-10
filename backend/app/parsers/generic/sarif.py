import json
import math
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry
from ..validation import ScanValidationError


def sarif_severity(result: dict, rule: dict) -> tuple[Severity, Optional[float]]:
    score = rule.get("properties", {}).get("security-severity")
    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError) as error:
            raise ScanValidationError("SARIF security-severity must be a score from 0 to 10") from error
        if not math.isfinite(score) or not 0 <= score <= 10:
            raise ScanValidationError("SARIF security-severity must be a score from 0 to 10")
        severity = (
            Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7
            else Severity.MEDIUM if score >= 4 else Severity.LOW if score > 0
            else Severity.INFO
        )
        return severity, score
    level = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
    levels = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}
    if level not in levels:
        raise ScanValidationError("Invalid SARIF result level")
    return levels[level], None


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
                rule_id = result.get("ruleId")
                if not rule_id and "ruleIndex" in result:
                    index = result["ruleIndex"]
                    rule_list = tool_info.get("rules", [])
                    if type(index) is not int or not 0 <= index < len(rule_list):
                        raise ScanValidationError("SARIF ruleIndex does not reference a rule")
                    rule_id = rule_list[index]["id"]
                rule_info = rules.get(rule_id, {})
                
                severity, cvss_score = sarif_severity(result, rule_info)
                
                locations = result.get("locations", [])
                file_path = None
                line_number = None
                asset = "unknown"
                
                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    if "uri" not in artifact and "index" in artifact:
                        artifacts = run.get("artifacts", [])
                        index = artifact["index"]
                        if type(index) is not int or not 0 <= index < len(artifacts):
                            raise ScanValidationError("SARIF artifact index does not reference an artifact")
                        artifact = artifacts[index].get("location", {})
                    file_path = artifact.get("uri")
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
                    description = message.get("text", message.get("markdown", ""))
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
                    severity=severity,
                    cvss_score=cvss_score,
                    source_id=rule_id,
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
