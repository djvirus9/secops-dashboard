import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ProgpilotParser(BaseParser):
    name = "progpilot"
    display_name = "ProgPilot"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "ProgPilot PHP static analysis security tool"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return "vuln_name" in first and "vuln_type" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for result in data:
            vuln_name = result.get("vuln_name") or "Unknown"
            vuln_type = result.get("vuln_type", "")
            vuln_cwe = result.get("vuln_cwe")
            vuln_description = result.get("vuln_description", "")
            vuln_file = result.get("vuln_file") or result.get("sink_file")
            vuln_line = result.get("vuln_line") or result.get("sink_line")
            source_name = result.get("source_name")
            source_line = result.get("source_line")
            source_file = result.get("source_file")
            sink_name = result.get("sink_name")
            sink_file = result.get("sink_file")
            sink_line = result.get("sink_line")
            tainted_flow = result.get("tainted_flow")
            vuln_rule = result.get("vuln_rule")
            vuln_column = result.get("vuln_column")

            description = f"**vuln_type:** {vuln_type}\n"
            if source_name:
                description += f"**source_name:** {source_name}\n"
            if source_line is not None:
                description += f"**source_line:** {source_line}\n"
            if source_file:
                description += f"**source_file:** {source_file}\n"
            if tainted_flow is not None:
                description += f"**tainted_flow:** {tainted_flow}\n"
            if sink_name:
                description += f"**sink_name:** {sink_name}\n"
            if vuln_rule:
                description += f"**vuln_rule:** {vuln_rule}\n"
            if vuln_column is not None:
                description += f"**vuln_column:** {vuln_column}\n"
            if vuln_description:
                description += f"**vuln_description:** {vuln_description}\n"

            # File path: prefer sink_file, then vuln_file
            file_path = sink_file or vuln_file
            # Line: prefer sink_line, then vuln_line
            line_raw = sink_line or vuln_line
            line_number = None
            if line_raw is not None:
                try:
                    line_number = int(line_raw)
                except (ValueError, TypeError):
                    pass

            # CWE
            cwe_id = None
            if vuln_cwe:
                cwe_str = str(vuln_cwe)
                if "CWE_" in cwe_str:
                    try:
                        cwe_id = int(cwe_str.split("CWE_")[1])
                    except (ValueError, IndexError):
                        pass
                elif cwe_str.isdigit():
                    cwe_id = int(cwe_str)

            findings.append(ParsedFinding(
                title=vuln_name,
                severity=Severity.normalize("medium"),
                tool="progpilot",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation="",
                raw_data=result,
            ))
        return findings
