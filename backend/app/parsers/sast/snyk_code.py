import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SnykCodeParser(BaseParser):
    name = "snyk_code"
    display_name = "Snyk Code"
    category = ScannerCategory.SAST
    file_types = ["json", "sarif"]
    description = "Snyk Code SAST scanner (SARIF output format)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if "runs" not in data:
                return False
            for run in data.get("runs", []):
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "").lower()
                if "snyk" in tool_name or "snykcode" in tool_name or "snyk code" in tool_name:
                    return True
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for run in data.get("runs", []):
            tool_info = run.get("tool", {}).get("driver", {})

            rules = {}
            for rule in tool_info.get("rules", []):
                rules[rule["id"]] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_info = rules.get(rule_id, {})
                props = result.get("properties", {})

                # Snyk Code uses priorityScore for severity
                score = props.get("priorityScore", 0)
                if score <= 399:
                    severity = Severity.LOW
                elif score <= 699:
                    severity = Severity.MEDIUM
                elif score <= 899:
                    severity = Severity.HIGH
                else:
                    severity = Severity.CRITICAL

                # Fallback to SARIF level if no priorityScore
                if score == 0:
                    level = result.get("level", "warning")
                    level_map = {
                        "error": Severity.HIGH,
                        "warning": Severity.MEDIUM,
                        "note": Severity.LOW,
                        "none": Severity.INFO,
                    }
                    severity = level_map.get(level, Severity.MEDIUM)

                locations = result.get("locations", [])
                file_path = None
                line_number = None

                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    file_path = artifact.get("uri")
                    region = phys.get("region", {})
                    line_number = region.get("startLine")

                # Title: ruleId + file
                title = f"{rule_id}_{file_path}" if file_path else rule_id

                # Description
                message = result.get("message", {})
                msg_text = message.get("text", "") if isinstance(message, dict) else str(message)
                description_parts = [
                    f"**ruleId**: {rule_id}",
                    f"**message**: {msg_text}",
                    f"**score**: {props.get('priorityScore', 0)}",
                    f"**isAutofixable**: {props.get('isAutofixable', False)}",
                ]
                if file_path:
                    description_parts.append(f"**uri**: {file_path}")
                if line_number:
                    description_parts.append(f"**startLine**: {line_number}")

                # CWE
                cwe_id = None
                tags = rule_info.get("properties", {}).get("tags", [])
                for tag in tags:
                    if "cwe" in str(tag).lower():
                        try:
                            cwe_id = int(str(tag).split("-")[-1])
                        except (ValueError, IndexError):
                            pass
                        break

                short_desc = rule_info.get("shortDescription", {})
                rule_title = short_desc.get("text", rule_id) if isinstance(short_desc, dict) else (str(short_desc) or rule_id)

                findings.append(ParsedFinding(
                    title=title or rule_title,
                    severity=severity,
                    tool="snyk_code",
                    description="\n".join(description_parts),
                    asset=file_path or "unknown",
                    file_path=file_path,
                    line_number=line_number,
                    cwe_id=cwe_id,
                    cve_id=None,
                    cvss_score=None,
                    recommendation=rule_info.get("help", {}).get("text", "") if isinstance(rule_info.get("help"), dict) else "",
                    references=[rule_info.get("helpUri")] if rule_info.get("helpUri") else [],
                    tags=tags,
                    raw_data=result,
                ))
        return findings
