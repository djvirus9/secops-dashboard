import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WpscanParser(BaseParser):
    name = "wpscan"
    display_name = "WPScan"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "WPScan WordPress vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and (
                "interesting_findings" in data
                or "plugins" in data
                or "version" in data
                or "target_url" in data
                or "wordpress" in str(data.get("banner", "")).lower()
            )
        except Exception:
            return False

    def _generate_references(self, node: dict) -> List[str]:
        refs = []
        for ref_type, items in node.items():
            for item in items:
                if ref_type == "url":
                    refs.append(item)
                elif ref_type == "wpvulndb":
                    refs.append(f"https://wpscan.com/vulnerability/{item}")
                elif ref_type == "cve":
                    refs.append(f"https://nvd.nist.gov/vuln/detail/CVE-{item}")
                else:
                    refs.append(f"{ref_type}: {item}")
        return refs

    def _parse_vulnerabilities(
        self, vulnerabilities: list, asset: str, plugin: Optional[str] = None
    ) -> List[ParsedFinding]:
        findings = []
        for vul in vulnerabilities:
            title = vul.get("title", "Unknown WordPress Vulnerability")
            refs_node = vul.get("references", {})
            references = self._generate_references(refs_node)

            cve_id = None
            cve_list = refs_node.get("cve", [])
            if cve_list:
                cve_id = f"CVE-{cve_list[0]}"

            description_parts = [f"**Title:** {title}"]
            if plugin:
                description_parts.append(f"**Plugin:** {plugin}")
            if vul.get("fixed_in"):
                description_parts.append(f"**Fixed In:** {vul['fixed_in']}")

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.MEDIUM,
                tool="wpscan",
                description="\n".join(description_parts),
                asset=asset,
                cwe_id=1035,
                cve_id=cve_id,
                cvss_score=None,
                recommendation=f"Update to version {vul['fixed_in']}" if vul.get("fixed_in") else "Update to the latest version",
                references=references,
                raw_data=vul,
            ))
        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        target_url = data.get("target_url", "unknown")

        # Plugin vulnerabilities
        for plugin_name, plugin_data in data.get("plugins", {}).items():
            vulns = plugin_data.get("vulnerabilities", [])
            if vulns:
                findings.extend(self._parse_vulnerabilities(vulns, target_url, plugin=plugin_name))

        # WordPress version vulnerabilities
        version_node = data.get("version", {})
        if version_node and version_node.get("vulnerabilities"):
            findings.extend(self._parse_vulnerabilities(
                version_node["vulnerabilities"], target_url
            ))

        # Interesting findings
        for finding_item in data.get("interesting_findings", []):
            url = finding_item.get("url", target_url)
            to_s = finding_item.get("to_s", finding_item.get("type", "Interesting Finding"))
            title = f"Interesting finding: {to_s}"

            description_parts = [
                f"**Type:** {finding_item.get('type', '')}",
                f"**URL:** {url}",
            ]
            entries = finding_item.get("interesting_entries", [])
            if entries:
                description_parts.append(f"**Details:** {' '.join(entries)}")

            refs_node = finding_item.get("references", {})
            references = self._generate_references(refs_node)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.INFO,
                tool="wpscan",
                description="\n".join(description_parts),
                asset=url,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation="Review and restrict access to this resource if sensitive.",
                references=references,
                raw_data=finding_item,
            ))

        return findings
