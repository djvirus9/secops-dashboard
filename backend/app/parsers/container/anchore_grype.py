import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AnchoreGrypeParser(BaseParser):
    name = "anchore_grype"
    display_name = "Anchore Grype"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Anchore Grype container vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            if "matches" not in data:
                return False
            matches = data["matches"]
            if not isinstance(matches, list) or len(matches) == 0:
                return True  # empty matches is valid grype output
            first = matches[0]
            return "vulnerability" in first and "artifact" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        for item in data.get("matches", []):
            vulnerability = item.get("vulnerability", {})
            artifact = item.get("artifact", {})
            match_details = item.get("matchDetails", [])
            related_vulns = item.get("relatedVulnerabilities", [])

            vuln_id = vulnerability.get("id", "Unknown")
            severity_raw = vulnerability.get("severity", "Unknown")
            severity = self._convert_severity(severity_raw)

            artifact_name = artifact.get("name", "unknown")
            artifact_version = artifact.get("version", "unknown")
            artifact_purl = artifact.get("purl", "")

            # Extract file path from artifact locations
            file_path = None
            locations = artifact.get("locations", [])
            if locations and locations[0].get("path"):
                file_path = locations[0]["path"]

            title = f"{vuln_id} in {artifact_name}:{artifact_version}"

            # Build description
            description_parts = []
            vuln_namespace = vulnerability.get("namespace")
            vuln_description = vulnerability.get("description", "")
            if vuln_namespace:
                description_parts.append(f"**Vulnerability Namespace:** {vuln_namespace}")
            if vuln_description:
                description_parts.append(f"**Vulnerability Description:** {vuln_description}")
            if related_vulns:
                rel_desc = related_vulns[0].get("description", "")
                if rel_desc and rel_desc != vuln_description:
                    description_parts.append(f"**Related Vulnerability Description:** {rel_desc}")
            if artifact_purl:
                description_parts.append(f"**Package URL:** {artifact_purl}")

            # Extract matchers for tags
            tags = ["anchore", "grype", "container"]
            if match_details:
                if isinstance(match_details, dict):
                    matcher = match_details.get("matcher", "")
                    if matcher:
                        tags.append(matcher.replace("-matcher", ""))
                elif isinstance(match_details, list):
                    for md in match_details:
                        if isinstance(md, dict) and md.get("matcher"):
                            tag = md["matcher"].replace("-matcher", "")
                            if tag not in tags:
                                tags.append(tag)
                    if match_details:
                        matcher_str = match_details[0].get("matcher", "") if isinstance(match_details[0], dict) else ""
                        description_parts.append(f"**Matcher:** {matcher_str}")

            description = "\n".join(description_parts)

            # Fix versions
            fix_versions = []
            if "fix" in vulnerability:
                fix_versions = vulnerability["fix"].get("versions", [])
            recommendation = ""
            if fix_versions:
                recommendation = "Upgrade to version: " + ", ".join(fix_versions)

            # CVSS score
            cvss_score = None
            vuln_cvss = vulnerability.get("cvss", [])
            if not vuln_cvss and related_vulns:
                vuln_cvss = related_vulns[0].get("cvss", [])
            if vuln_cvss:
                cvss_score = self._extract_cvss_score(vuln_cvss)

            # References
            refs = []
            vuln_datasource = vulnerability.get("dataSource")
            if vuln_datasource:
                refs.append(vuln_datasource)
            for url in vulnerability.get("urls", []):
                if url not in refs:
                    refs.append(url)
            if related_vulns:
                rel_ds = related_vulns[0].get("dataSource")
                if rel_ds and rel_ds not in refs:
                    refs.append(rel_ds)
                for url in related_vulns[0].get("urls", []):
                    if url not in refs:
                        refs.append(url)

            # CVE IDs
            vulnerability_ids = []
            if vuln_id:
                vulnerability_ids.append(vuln_id)
            for rel in related_vulns:
                rel_id = rel.get("id")
                if rel_id and rel_id not in vulnerability_ids:
                    vulnerability_ids.append(rel_id)

            cve_id = vuln_id if vuln_id.startswith("CVE-") else (
                vulnerability_ids[1] if len(vulnerability_ids) > 1 and vulnerability_ids[1].startswith("CVE-") else None
            )

            dupe_key = f"{vuln_id}|{artifact_name}|{artifact_version}"
            if dupe_key in seen:
                continue
            seen.add(dupe_key)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity),
                tool="anchore_grype",
                description=description,
                asset=artifact_name,
                file_path=file_path,
                cve_id=cve_id,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=refs,
                tags=tags,
                raw_data=item,
            ))

        return findings

    def _convert_severity(self, val: str) -> str:
        if val in ("Unknown", "Negligible"):
            return "info"
        return val.lower()

    def _extract_cvss_score(self, cvss_list: list) -> Optional[float]:
        for cvss_item in cvss_list:
            if not isinstance(cvss_item, dict):
                continue
            metrics = cvss_item.get("metrics", {})
            base_score = metrics.get("baseScore")
            if base_score is not None:
                try:
                    return float(base_score)
                except Exception:
                    pass
        return None
