import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class NpmAudit7PlusParser(BaseParser):
    name = "npm_audit_7_plus"
    display_name = "npm audit v7+"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Node.js npm audit v7+ vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            # npm audit --json (v7+): top-level auditReportVersion >= 2
            if data.get("auditReportVersion") and "vulnerabilities" in data:
                return True
            # npm audit fix --dry-run --json: nested audit.auditReportVersion
            if "audit" in data and data["audit"].get("auditReportVersion"):
                return True
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []

        # Unwrap nested audit format
        if "audit" in data and data["audit"].get("auditReportVersion"):
            vuln_tree = data["audit"].get("vulnerabilities", {})
        else:
            vuln_tree = data.get("vulnerabilities", {})

        seen = set()
        for pkg_name, node in vuln_tree.items():
            title, description, severity_str, cwe_id, cvss_score, references, recommendation = self._extract_node(node, vuln_tree)

            dedup_key = title + severity_str
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="npm_audit_7_plus",
                description=description,
                asset=node.get("name", pkg_name),
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=references,
                tags=["npm", pkg_name],
                raw_data=node,
            ))

        return findings

    def _extract_node(self, node: dict, tree: dict) -> tuple:
        severity_str = node.get("severity", "info")
        via = node.get("via", [])

        title = ""
        description = ""
        cwe_id = None
        cvss_score = None
        references = []
        recommendation = ""

        if via and isinstance(via[0], str):
            # Indirect vulnerability — the title is the package name
            title = node.get("name", "Unknown")
            description = self._build_description(node, tree)
        elif via and isinstance(via[0], dict):
            via_item = via[0]
            title = via_item.get("title", node.get("name", "Unknown"))
            description = self._build_description(node, tree)
            if via_item.get("url"):
                references.append(via_item["url"])
            cwe_raw = via_item.get("cwe", [])
            if cwe_raw:
                try:
                    cwe_id = int(str(cwe_raw[0]).replace("CWE-", "").strip())
                except Exception:
                    pass
            cvss_info = via_item.get("cvss", {})
            if isinstance(cvss_info, dict) and cvss_info.get("score"):
                try:
                    cvss_score = float(cvss_info["score"])
                except Exception:
                    pass
            # Collect remaining references from additional via items
            for extra_via in via[1:]:
                if isinstance(extra_via, dict) and extra_via.get("url"):
                    references.append(extra_via["url"])
        else:
            title = node.get("name", "Unknown")
            description = self._build_description(node, tree)

        fix_available = node.get("fixAvailable")
        if isinstance(fix_available, dict):
            recommendation = f"Update {fix_available.get('name', '')} to version {fix_available.get('version', '')}"
        else:
            recommendation = "No specific mitigation provided by tool."

        return title, description, severity_str, cwe_id, cvss_score, references, recommendation

    def _build_description(self, node: dict, tree: dict) -> str:
        name = node.get("name", "")
        rng = node.get("range", "")
        severity = node.get("severity", "")
        lines = [
            f"{name} {rng}",
            f"Severity: {severity}",
        ]

        for via in node.get("via", []):
            if isinstance(via, str):
                lines.append(f"Depends on vulnerable versions of {via}")
            elif isinstance(via, dict):
                lines.append(f"{via.get('title', '')} - {via.get('url', '')}")

        fix_available = node.get("fixAvailable")
        if isinstance(fix_available, dict):
            lines.append(f"Fix Available: Update {fix_available.get('name', '')} to version {fix_available.get('version', '')}")
        else:
            lines.append("No specific mitigation provided by tool.")

        for node_path in node.get("nodes", []):
            lines.append(node_path)

        return "\n".join(lines)
