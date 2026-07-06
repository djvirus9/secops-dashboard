import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class OssIndexDevauditParser(BaseParser):
    name = "ossindex_devaudit"
    display_name = "OSS Index DevAudit"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Sonatype OSSIndex DevAudit SCA scan"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            packages = data.get("Packages")
            if not isinstance(packages, list) or len(packages) == 0:
                return False
            first = packages[0]
            return "Package" in first and "Vulnerabilities" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        for package in data.get("Packages", []):
            package_data = package.get("Package", {})
            pkg_manager = package_data.get("pm", "unknown")
            pkg_name = package_data.get("name", "unknown")
            pkg_version = package_data.get("version", "unknown")
            asset = f"{pkg_manager}:{pkg_name}"

            for vuln in package.get("Vulnerabilities", []):
                vuln_id = vuln.get("id", "")
                if vuln_id in seen:
                    continue
                seen.add(vuln_id)

                cvss_score_raw = vuln.get("cvssScore", "")
                try:
                    cvss_score = float(cvss_score_raw)
                except Exception:
                    cvss_score = None

                severity = self._cvss_score_to_severity(cvss_score_raw)

                cwe_data = vuln.get("cwe", "CWE-1035")
                if not cwe_data or not str(cwe_data).startswith("CWE"):
                    cwe_data = "CWE-1035"
                cwe_id = None
                try:
                    cwe_id = int(str(cwe_data).split("-")[1])
                except Exception:
                    pass

                title = (
                    f"{pkg_manager}:{pkg_name} - "
                    f"({pkg_version}, {cwe_data})"
                )

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool="ossindex_devaudit",
                    description=vuln.get("title", ""),
                    asset=asset,
                    cwe_id=cwe_id,
                    cvss_score=cvss_score,
                    recommendation="Upgrade the component to the latest non-vulnerable version, or remove the package if it is not in use.",
                    references=[vuln.get("reference")] if vuln.get("reference") else [],
                    tags=["ossindex", pkg_manager, pkg_name],
                    raw_data=vuln,
                ))

        return findings

    def _cvss_score_to_severity(self, score_raw) -> str:
        try:
            score = float(score_raw)
        except Exception:
            return "info"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"
