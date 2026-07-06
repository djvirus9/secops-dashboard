import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class PhpSymfonySecurityCheckParser(BaseParser):
    name = "php_symfony_security_check"
    display_name = "PHP Symfony Security Check"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "PHP Symfony Security Checker for known vulnerable dependencies"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            # Each key is a package name; each value has 'version' and 'advisories'
            for _pkg_name, pkg_data in data.items():
                if isinstance(pkg_data, dict) and "advisories" in pkg_data and "version" in pkg_data:
                    return True
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for dependency_name, dependency_data in data.items():
            if not isinstance(dependency_data, dict):
                continue
            version = dependency_data.get("version", "unknown")
            if version and version.startswith("v"):
                version = version[1:]

            advisories = dependency_data.get("advisories", [])
            for advisory in advisories:
                cve = advisory.get("cve", "")
                link = advisory.get("link", "")
                adv_title = advisory.get("title", "")

                title = f"{dependency_name} - ({version}, {cve})" if cve else f"{dependency_name} - ({version})"
                description = adv_title

                references = [link] if link else []

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize("info"),
                    tool="php_symfony_security_check",
                    description=description,
                    asset=dependency_name,
                    file_path=None,
                    line_number=None,
                    cwe_id=1035,
                    cve_id=cve if cve else None,
                    cvss_score=None,
                    recommendation="Upgrade to a non-vulnerable version.",
                    references=references,
                    raw_data=advisory,
                ))
        return findings
