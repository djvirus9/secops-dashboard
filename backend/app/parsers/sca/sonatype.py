import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SonatypeParser(BaseParser):
    name = "sonatype"
    display_name = "Sonatype Nexus IQ"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "Sonatype Nexus IQ application security scan"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            if "components" not in data:
                return False
            components = data["components"]
            if not isinstance(components, list) or len(components) == 0:
                return False
            first = components[0]
            return "securityData" in first or "componentIdentifier" in first or "packageUrl" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []

        for component in data.get("components", []):
            security_data = component.get("securityData")
            if not security_data:
                continue
            issues = security_data.get("securityIssues", [])
            if not issues:
                continue

            component_id = self._get_component_id(component)
            component_name, component_version = self._get_name_version(component)
            file_path = None
            pathnames = component.get("pathnames", [])
            if pathnames:
                file_path = " ".join(pathnames)[:1000]

            for issue in issues:
                raw_severity = issue.get("severity", 0)
                try:
                    raw_severity = float(raw_severity)
                except Exception:
                    raw_severity = 0.0

                severity = self._cvss_to_severity(raw_severity)
                reference = issue.get("reference", "Unknown")
                title = f"{reference} - {component_id}"

                description = f"Hash: {component.get('hash', 'N/A')}\n\n{component_id}"
                threat_category = issue.get("threatCategory", "").title()

                cve_id = None
                if issue.get("source") == "cve":
                    cve_id = reference

                cwe_id = None
                if "cwe" in issue:
                    try:
                        cwe_id = int(str(issue["cwe"]).replace("CWE-", "").strip())
                    except Exception:
                        pass

                cvss_score = None
                if "cvssVector" in issue:
                    try:
                        cvss_score = float(raw_severity)
                    except Exception:
                        pass

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity),
                    tool="sonatype",
                    description=description,
                    asset=component_name or "unknown",
                    file_path=file_path,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    cvss_score=cvss_score,
                    recommendation=issue.get("status", ""),
                    references=[issue.get("url")] if issue.get("url") else [],
                    tags=["sonatype", threat_category] if threat_category else ["sonatype"],
                    raw_data=issue,
                ))

        return findings

    def _get_component_id(self, component: dict) -> str:
        if component.get("packageUrl"):
            return component["packageUrl"]
        ident = component.get("componentIdentifier", {})
        fmt = ident.get("format", "")
        coords = ident.get("coordinates", {})
        if fmt == "maven":
            return f"{coords.get('groupId', '')}:{coords.get('artifactId', '')}:{coords.get('version', '')}"
        name = coords.get("packageId", coords.get("name", "unknown"))
        version = coords.get("version", "")
        return f"{name}:{version}" if version else name

    def _get_name_version(self, component: dict) -> tuple:
        ident = component.get("componentIdentifier", {})
        fmt = ident.get("format", "")
        coords = ident.get("coordinates", {})
        version = coords.get("version", "")
        if fmt == "maven":
            name = coords.get("artifactId", "unknown")
        else:
            name = coords.get("packageId", coords.get("name", "unknown"))
        return name, version

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"
