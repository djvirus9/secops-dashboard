import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AnchoreCTLVulnsParser(BaseParser):
    name = "anchorectl_vulns"
    display_name = "AnchoreCTL Vulnerabilities"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "AnchoreCTL vulnerability scan report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or len(data) == 0:
                return False
            first = data[0]
            if not isinstance(first, dict):
                return False
            # AnchoreCTL vulns format uses camelCase keys
            return "vuln" in first and "packageType" in first and "feedGroup" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        seen = set()

        for item in data:
            if not isinstance(item, dict):
                continue

            vuln_id = item.get("vuln", "unknown")
            package = item.get("package", "unknown")
            package_type = item.get("packageType", "unknown")
            package_name = item.get("packageName", package)
            package_version = item.get("packageVersion", "unknown")
            package_path = item.get("packagePath", "unknown")
            image_digest = item.get("imageDigest", "unknown")
            feed = item.get("feed", "")
            feed_group = item.get("feedGroup", "")

            dupe_key = "|".join([image_digest, feed, feed_group, package_name, package_version, package_path, vuln_id])
            if dupe_key in seen:
                continue
            seen.add(dupe_key)

            sev = item.get("severity", "Unknown")
            if sev in ("Negligible", "Unknown"):
                sev = "info"

            fix = item.get("fix", "None")
            if fix != "None":
                recommendation = f"Upgrade to {package_name} {fix}"
                fix_available = True
            else:
                recommendation = "No fix available"
                fix_available = False

            # CVSS score extraction (camelCase keys for AnchoreCTL)
            cvss_score = None
            if feed in ("nvdv2", "vulnerabilities"):
                nvd_data = item.get("nvdData", [])
                if nvd_data:
                    try:
                        cvss_score = float(nvd_data[0]["cvssV3"]["baseScore"])
                        if cvss_score < 0 or cvss_score > 10:
                            cvss_score = None
                    except Exception:
                        pass
            if cvss_score is None:
                vendor_data = item.get("vendorData", [])
                for vd in vendor_data:
                    try:
                        score = float(vd["cvssV3"]["baseScore"])
                        if score >= 0:
                            cvss_score = score
                            break
                    except Exception:
                        continue

            description = (
                f"**Image hash**: {image_digest}\n\n"
                f"**Package**: {package}\n\n"
                f"**Package path**: {package_path}\n\n"
                f"**Package type**: {package_type}\n\n"
                f"**Feed**: {feed}/{feed_group}\n\n"
                f"**CPE**: {item.get('packageCpe', 'N/A')}\n\n"
                f"**Description**: {item.get('description', 'N/A')}\n\n"
            )

            findings.append(ParsedFinding(
                title=f"{vuln_id} - {package}({package_type})",
                severity=Severity.normalize(sev),
                tool="anchorectl_vulns",
                description=description,
                asset=image_digest,
                file_path=package_path if package_path != "unknown" else None,
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                cvss_score=cvss_score,
                recommendation=recommendation,
                references=[item.get("url")] if item.get("url") else [],
                tags=["anchorectl", "container", package_type],
                raw_data=item,
            ))

        return findings
