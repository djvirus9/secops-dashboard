import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CheckmarxOsaParser(BaseParser):
    name = "checkmarx_osa"
    display_name = "Checkmarx OSA"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Checkmarx Open Source Analysis (OSA) for dependencies"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or len(data) != 2:
                return False
            # Expect [vulnerabilities_array, libraries_array]
            # Vulnerabilities have 'libraryId' and 'severity'
            if not isinstance(data[0], list) or not isinstance(data[1], list):
                return False
            if data[0]:
                first = data[0][0]
                return "libraryId" in first and "severity" in first
            if data[1]:
                first = data[1][0]
                return "id" in first and "name" in first
            return True
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        if len(data) != 2:
            return findings

        vulnerabilities = data[0]
        libraries_list = data[1]

        # Build library lookup by id
        libraries_dict = {lib["id"]: lib for lib in libraries_list if "id" in lib}

        for item in vulnerabilities:
            library_id = item.get("libraryId")
            library = libraries_dict.get(library_id, {})

            lib_name = library.get("name", "Unknown")
            lib_version = library.get("version", "Unknown")

            state = item.get("state", {})
            state_name = state.get("name", "TO_VERIFY") if isinstance(state, dict) else str(state)

            severity_obj = item.get("severity", {})
            severity_name = severity_obj.get("name", "Info") if isinstance(severity_obj, dict) else str(severity_obj)

            cve = item.get("cveName", "NC")
            title = f"{lib_name} {lib_version} | {cve}"

            description = item.get("description", "")
            recommendation = item.get("recommendations", "")
            references = [item.get("url")] if item.get("url") else []

            cvss_score = item.get("score")
            cve_id = cve if cve != "NC" else None

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_name),
                tool="checkmarx_osa",
                description=description,
                asset=lib_name,
                file_path=None,
                line_number=None,
                cwe_id=1035,
                cve_id=cve_id,
                cvss_score=float(cvss_score) if cvss_score is not None else None,
                recommendation=recommendation,
                references=references,
                raw_data=item,
            ))
        return findings
