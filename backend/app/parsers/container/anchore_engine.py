import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AnchoreEngineParser(BaseParser):
    name = "anchore_engine"
    display_name = "Anchore Engine"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Anchore Engine CLI JSON vulnerability report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            # With metadata format: {"metadata": {...}, "securityEvaluation": [...]}
            if "metadata" in data and "securityEvaluation" in data:
                return True
            # Without metadata format: {"vulnerabilities": [...]} with anchore-specific keys
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                vulns = data["vulnerabilities"]
                if vulns:
                    first = vulns[0]
                    return "package_path" in first or "package_cpe" in first or "feed" in first
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        if data.get("metadata"):
            return self._parse_with_metadata(data)
        return self._parse_without_metadata(data)

    def _parse_with_metadata(self, data: dict) -> List[ParsedFinding]:
        findings = []
        seen = set()
        metadata = data.get("metadata", {})
        image_digest = metadata.get("imageDigest", metadata.get("image_digest", "unknown"))

        for item in data.get("securityEvaluation", []):
            vuln_id = item.get("vulnerabilityId", "Unknown")
            package = item.get("package", "unknown")
            package_type = item.get("packageType", "unknown")
            path = item.get("path", "unknown")

            dupe_key = "|".join([
                item.get("cves", "None"),
                package,
                package_type,
                path,
                item.get("severity", "None"),
            ])
            if dupe_key in seen:
                continue
            seen.add(dupe_key)

            sev = item.get("severity", "Unknown")
            if sev.lower() in ("negligible", "unknown"):
                sev = "info"

            cvss_score_raw = item.get("nvdCvssBaseScore")
            cvss_score = None
            if cvss_score_raw is not None:
                try:
                    cvss_score = float(cvss_score_raw)
                    if cvss_score < 0 or cvss_score > 10:
                        cvss_score = None
                except Exception:
                    pass

            fix_available = item.get("fixAvailable")
            recommendation = ""
            if fix_available and fix_available != "None":
                recommendation = f"Upgrade to: {fix_available}\nURL: {item.get('link', '')}"

            description = (
                f"**Image hash**: {image_digest}\n\n"
                f"**Package**: {package}\n\n"
                f"**Package path**: {path}\n\n"
                f"**Package type**: {package_type}\n\n"
            )

            cve_id = item.get("cves") or None

            findings.append(ParsedFinding(
                title=f"{vuln_id}-{package}({package_type})",
                severity=Severity.normalize(sev),
                tool="anchore_engine",
                description=description,
                asset=image_digest,
                file_path=path if path != "unknown" else None,
                cve_id=cve_id,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=[item.get("link")] if item.get("link") else [],
                tags=["anchore", "container", package_type],
                raw_data=item,
            ))
        return findings

    def _parse_without_metadata(self, data: dict) -> List[ParsedFinding]:
        findings = []
        seen = set()

        for item in data.get("vulnerabilities", []):
            vuln_id = item.get("vuln", "unknown")
            package = item.get("package", "unknown")
            package_type = item.get("package_type", "unknown")
            package_path = item.get("package_path", "unknown")
            package_name = item.get("package_name", package)
            package_version = item.get("package_version", "unknown")
            image_digest = item.get("image_digest", item.get("imageDigest", "unknown"))
            feed = item.get("feed", "")
            feed_group = item.get("feed_group", "")

            dupe_key = "|".join([image_digest, feed, feed_group, package_name, package_version, package_path, vuln_id])
            if dupe_key in seen:
                continue
            seen.add(dupe_key)

            sev = item.get("severity", "Unknown")
            if sev in ("Negligible", "Unknown"):
                sev = "info"

            fix = item.get("fix", "None")
            recommendation = f"Upgrade to {package_name} {fix}\nURL: {item.get('url', '')}" if fix != "None" else "No fix available"

            cvss_score = None
            nvd_data = item.get("nvd_data", [])
            if nvd_data:
                try:
                    score = nvd_data[0]["cvss_v3"]["base_score"]
                    cvss_score = float(score)
                    if cvss_score < 0 or cvss_score > 10:
                        cvss_score = None
                except Exception:
                    pass
            if cvss_score is None:
                vendor_data = item.get("vendor_data", [])
                for vd in vendor_data:
                    try:
                        score = vd["cvss_v3"]["base_score"]
                        if float(score) >= 0:
                            cvss_score = float(score)
                            break
                    except Exception:
                        continue

            description = (
                f"**Image hash**: {image_digest}\n\n"
                f"**Package**: {package}\n\n"
                f"**Package path**: {package_path}\n\n"
                f"**Package type**: {package_type}\n\n"
                f"**Feed**: {feed}/{feed_group}\n\n"
                f"**CPE**: {item.get('package_cpe', 'N/A')}\n\n"
                f"**Description**: {item.get('description', 'N/A')}\n\n"
            )

            findings.append(ParsedFinding(
                title=f"{vuln_id} - {package}({package_type})",
                severity=Severity.normalize(sev),
                tool="anchore_engine",
                description=description,
                asset=image_digest,
                file_path=package_path if package_path != "unknown" else None,
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=[item.get("url")] if item.get("url") else [],
                tags=["anchore", "container", package_type],
                raw_data=item,
            ))
        return findings
