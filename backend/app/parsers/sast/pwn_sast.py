import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PwnSastParser(BaseParser):
    name = "pwn_sast"
    display_name = "PWN SAST"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "PWN SAST source code scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "report_name" in data and "data" in data and isinstance(data.get("data"), list)
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        data_arr = data.get("data", [])

        for data_hash in data_arr:
            security_references = data_hash.get("security_references")
            if security_references:
                sast_module = security_references.get("sast_module")
                cwe_raw = security_references.get("cwe_id")
                nist_uri = security_references.get("nist_800_53_uri", "")
                cwe_uri = security_references.get("cwe_uri", "")
                section = security_references.get("section", "")
            else:
                sast_module = None
                cwe_raw = None
                nist_uri = ""
                cwe_uri = ""
                section = ""

            filename_hash = data_hash.get("filename")
            if filename_hash:
                git_repo_root_uri = filename_hash.get("git_repo_root_uri", "")
                offending_file = filename_hash.get("entry", "")
            else:
                git_repo_root_uri = ""
                offending_file = ""

            line_no_and_contents = data_hash.get("line_no_and_contents", [])

            cwe_id = None
            if cwe_raw is not None:
                try:
                    cwe_id = int(cwe_raw)
                except (ValueError, TypeError):
                    pass

            for line in line_no_and_contents:
                line_no = line.get("line_no")
                contents = line.get("contents", "")
                author = line.get("author", "")
                offending_uri = f"{git_repo_root_uri}/{offending_file}" if git_repo_root_uri else offending_file

                title = f"{sast_module} Entry in {offending_file} Line: {line_no}"
                description = "\n".join([
                    f"SAST Module: {sast_module}",
                    f"Offending URI: {offending_uri}",
                    f"Line: {line_no}",
                    f"Committed By: {author}",
                    "Line Contents:",
                    f"```{contents}```",
                ])

                recommendation = f"NIST 800-53 Security Control Details: {nist_uri}"
                references = []
                if cwe_uri:
                    references.append(cwe_uri)
                if nist_uri:
                    references.append(nist_uri)

                line_number = None
                if line_no is not None:
                    try:
                        line_number = int(line_no)
                    except (ValueError, TypeError):
                        pass

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize("info"),
                    tool="pwn_sast",
                    description=description,
                    asset=offending_file or "unknown",
                    file_path=offending_file or None,
                    line_number=line_number,
                    cwe_id=cwe_id,
                    cve_id=None,
                    cvss_score=None,
                    recommendation=recommendation,
                    references=references,
                    raw_data=data_hash,
                ))
        return findings
