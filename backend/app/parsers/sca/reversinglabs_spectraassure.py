import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ReversinglabsSpectraassureParser(BaseParser):
    name = "reversinglabs_spectraassure"
    display_name = "ReversingLabs SpectraAssure"
    category = ScannerCategory.SCA
    file_types = ["json"]
    description = "ReversingLabs SpectraAssure software supply chain security scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            report = data.get("report", {})
            if not isinstance(report, dict):
                return False
            metadata = report.get("metadata", {})
            return "vulnerabilities" in metadata or "components" in metadata
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        report = data.get("report", {})
        metadata = report.get("metadata", {})
        vulnerabilities = metadata.get("vulnerabilities", {})
        components = metadata.get("components", {})
        dependencies = metadata.get("dependencies", {})

        # Process component -> vulnerability (direct)
        for comp_uuid, component in components.items():
            ident = component.get("identity", {})
            comp_vulns = ident.get("vulnerabilities", {})
            c_purl = ident.get("purl", "")
            comp_path = component.get("path", component.get("name", comp_uuid))
            comp_name = component.get("name", comp_uuid)
            comp_version = ident.get("version", "")

            for cve in comp_vulns.get("active", []):
                key = f"{cve}|{comp_uuid}|None"
                if key in seen:
                    continue
                seen.add(key)

                finding = self._make_finding(
                    cve=cve,
                    vulnerabilities=vulnerabilities,
                    component_name=comp_name,
                    component_version=comp_version,
                    component_path=comp_path,
                    component_purl=c_purl,
                    component_type="component",
                )
                if finding:
                    findings.append(finding)

            # Process component -> dependency -> vulnerability
            dep_uuids = ident.get("dependencies", [])
            for dep_uuid in dep_uuids:
                dependency = dependencies.get(dep_uuid, {})
                dep_vulns = dependency.get("vulnerabilities", {})
                dep_name = dependency.get("product", dep_uuid)
                dep_version = dependency.get("version", "")
                dep_purl = dependency.get("purl", "")

                for cve in dep_vulns.get("active", []):
                    key = f"{cve}|{comp_uuid}|{dep_uuid}"
                    if key in seen:
                        continue
                    seen.add(key)

                    finding = self._make_finding(
                        cve=cve,
                        vulnerabilities=vulnerabilities,
                        component_name=dep_name,
                        component_version=dep_version,
                        component_path=comp_path,
                        component_purl=dep_purl if dep_purl else c_purl,
                        component_type="dependency",
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def _make_finding(
        self,
        cve: str,
        vulnerabilities: dict,
        component_name: str,
        component_version: str,
        component_path: str,
        component_purl: str,
        component_type: str,
    ) -> Optional[ParsedFinding]:
        vuln_info = vulnerabilities.get(cve, {})
        if not vuln_info and not cve:
            return None

        cvss_info = vuln_info.get("cvss", {})
        score_raw = cvss_info.get("baseScore", 0.0)
        try:
            score = float(score_raw)
        except Exception:
            score = 0.0

        severity = self._score_to_severity(score)

        exploit_info = vuln_info.get("exploit", [])
        tags = []
        common_tags_map = {
            "FIXABLE": "Fix Available",
            "EXISTS": "Exploit Exists",
            "MALWARE": "Exploited by Malware",
            "MANDATE": "Patching Mandated",
            "UNPROVEN": "CVE Discovered",
        }
        for key in exploit_info:
            tag = common_tags_map.get(key)
            if tag:
                tags.append(tag)

        if component_purl:
            title = f"{cve} on {component_type} purl: {component_purl}"
            description = (
                f"On {component_type} purl: {component_purl} "
                f"version: {component_version} "
                f"path: {component_path}"
            )
        else:
            title = f"{cve} on {component_type} name: {component_name} version: {component_version}"
            description = (
                f"On {component_type} name: {component_name} "
                f"version: {component_version} "
                f"path: {component_path}"
            )

        return ParsedFinding(
            title=title,
            severity=Severity.normalize(severity),
            tool="reversinglabs_spectraassure",
            description=description,
            asset=component_name or "unknown",
            file_path=component_path or None,
            cve_id=cve,
            cvss_score=score if score > 0 else None,
            tags=["reversinglabs", "spectraassure"] + tags,
            raw_data=vuln_info,
        )

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"
