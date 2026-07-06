import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class YarnAuditParser(BaseParser):
    name = "yarn_audit"
    display_name = "Yarn Audit"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Yarn package manager security audit scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            stripped = content.strip()
            # Old yarn: NDJSON lines with {"type": "auditAdvisory", ...}
            if '"type"' in stripped and '"auditAdvisory"' in stripped:
                return True
            # Yarn 2+: NDJSON lines with {"value": ..., "children": {..., "ID": ...}}
            if '"value"' in stripped and '"children"' in stripped and '"ID"' in stripped:
                return True
            # audit-ci format: JSON with "advisories" key
            data = json.loads(stripped)
            if isinstance(data, dict) and "advisories" in data:
                # Distinguish from npm_audit by checking for yarn-specific keys or absence of npm metadata
                return True
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        stripped = content.strip()

        # Old yarn format: NDJSON with {"type": "auditAdvisory", ...}
        if '"type"' in stripped and '"auditAdvisory"' in stripped:
            return self._parse_yarn_v1(stripped)

        # Yarn 2+ format: NDJSON with {"value": ..., "children": {...}}
        if '"value"' in stripped and '"children"' in stripped and '"ID"' in stripped:
            return self._parse_yarn_v2(stripped)

        # audit-ci / JSON format
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and "advisories" in data:
                return self._parse_audit_ci(data)
        except Exception:
            pass

        return []

    def _parse_yarn_v1(self, content: str) -> List[ParsedFinding]:
        findings = []
        seen = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or "{" not in line:
                continue
            try:
                element = json.loads(line)
            except Exception:
                continue
            if element.get("type") != "auditAdvisory":
                continue
            advisory = element.get("data", {}).get("advisory", {})
            unique_key = str(advisory.get("id", "")) + str(advisory.get("module_name", ""))
            if unique_key in seen:
                continue
            seen.add(unique_key)

            cve_id = None
            cves = advisory.get("cves", [])
            if cves:
                cve_id = cves[0]

            cwe_id = None
            cwe_raw = advisory.get("cwe")
            if cwe_raw:
                try:
                    cwe_id = int(str(cwe_raw).replace("CWE-", "").strip())
                except Exception:
                    pass

            paths = ""
            for finding in advisory.get("findings", []):
                paths_list = finding.get("paths", [])[:25]
                paths += "\n  - " + str(finding.get("version", "")) + ":" + ",".join(paths_list)

            description = (
                advisory.get("url", "") + "\n"
                + advisory.get("overview", "") + "\n"
                + "Vulnerable Module: " + advisory.get("module_name", "") + "\n"
                + "Vulnerable Versions: " + str(advisory.get("vulnerable_versions", "")) + "\n"
                + "Patched Version: " + str(advisory.get("patched_versions", "")) + "\n"
                + "Vulnerable Paths: " + paths + "\n"
                + "CWE: " + str(advisory.get("cwe", "")) + "\n"
                + "Access: " + str(advisory.get("access", ""))
            )

            findings.append(ParsedFinding(
                title=advisory.get("title", f"Vulnerability in {advisory.get('module_name', 'unknown')}"),
                severity=Severity.normalize(advisory.get("severity", "moderate")),
                tool="yarn_audit",
                description=description,
                asset=advisory.get("module_name", "unknown"),
                cve_id=cve_id,
                cwe_id=cwe_id,
                recommendation=advisory.get("recommendation", ""),
                references=[advisory.get("url")] if advisory.get("url") else [],
                tags=["yarn", advisory.get("module_name", "")],
                raw_data=advisory,
            ))
        return findings

    def _parse_yarn_v2(self, content: str) -> List[ParsedFinding]:
        findings = []
        for line in content.splitlines():
            line = line.strip()
            if not line or "{" not in line:
                continue
            try:
                element = json.loads(line)
            except Exception:
                continue
            value = element.get("value")
            children = element.get("children")
            if children is None:
                continue

            child_id = children.get("ID", "")
            issue = children.get("Issue", "")
            severity_raw = children.get("Severity", "info")
            vuln_version = children.get("Vulnerable Versions", "")
            tree_versions = children.get("Tree Versions", [])
            dependents = children.get("Dependents", [])

            description = (
                issue + "\n"
                + "**Vulnerable Versions:** " + str(vuln_version) + "\n"
                + "**Dependents:** " + ", ".join(set(dependents)) + "\n"
            )

            findings.append(ParsedFinding(
                title=str(child_id),
                severity=Severity.normalize(str(severity_raw)),
                tool="yarn_audit",
                description=description,
                asset=str(value) if value else "unknown",
                tags=["yarn", str(value) if value else ""],
                raw_data=element,
            ))
        return findings

    def _parse_audit_ci(self, data: dict) -> List[ParsedFinding]:
        findings = []
        for advisory_id, advisory in data.get("advisories", {}).items():
            cve_id = None
            cves = advisory.get("cves", [])
            if cves:
                cve_id = cves[0]

            cwe_id = None
            cwe_list = advisory.get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                try:
                    cwe_id = int(str(cwe_list[0]).strip().replace("CWE-", ""))
                except Exception:
                    pass

            findings_list = advisory.get("findings", [{}])
            component_version = ""
            if findings_list:
                component_version = str(findings_list[0].get("version", ""))

            description = (
                "**findings:** " + str(advisory.get("findings", "")) + "\n"
                + "**vulnerable_versions:** " + str(advisory.get("vulnerable_versions", "")) + "\n"
                + "**patched_versions:** " + str(advisory.get("patched_versions", "")) + "\n"
                + "**overview:** " + str(advisory.get("overview", "")) + "\n"
            )

            findings.append(ParsedFinding(
                title=advisory.get("title", f"Advisory {advisory_id}"),
                severity=Severity.normalize(advisory.get("severity", "moderate")),
                tool="yarn_audit",
                description=description,
                asset=advisory.get("module_name", "unknown"),
                cve_id=cve_id,
                cwe_id=cwe_id,
                recommendation=advisory.get("recommendation", ""),
                references=[advisory.get("url")] if advisory.get("url") else [],
                tags=["yarn", advisory.get("module_name", "")],
                raw_data=advisory,
            ))
        return findings
