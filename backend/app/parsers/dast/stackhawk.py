import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class StackHawkParser(BaseParser):
    name = "stackhawk"
    display_name = "StackHawk"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "StackHawk API security testing (HawkScan)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and data.get("service") == "StackHawk"
                and "scanCompleted" in data
            )
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        completed_scan = data.get("scanCompleted", {})
        scan_meta = completed_scan.get("scan", {})
        application = scan_meta.get("application", "unknown")
        env = scan_meta.get("env", "")
        scan_url = completed_scan.get("scan", {}).get("scanURL", "")

        seen_plugin_ids = set()
        for raw_finding in completed_scan.get("findings", []):
            plugin_id = raw_finding.get("pluginId", "unknown")
            if plugin_id in seen_plugin_ids:
                continue
            seen_plugin_ids.add(plugin_id)

            plugin_name = raw_finding.get("pluginName", plugin_id)
            severity_str = raw_finding.get("severity", "info")
            host = raw_finding.get("host", "unknown")
            finding_url = raw_finding.get("findingURL", "")
            total_count = raw_finding.get("totalCount", 1)

            paths = raw_finding.get("paths", [])
            path_details = []
            for path in paths:
                path_details.append(
                    f"- {path.get('path', '')} [{path.get('status', '')}]: {path.get('pathURL', '')}"
                )

            description = f"View this finding in the StackHawk platform:\n{finding_url}\n"
            if path_details:
                description += "\n**Affected Paths:**\n" + "\n".join(path_details)
            if env:
                description += f"\n\n**Environment:** {env}"

            asset = host if host != "unknown" else scan_url or "unknown"

            findings.append(ParsedFinding(
                title=plugin_name,
                severity=Severity.normalize(severity_str),
                tool="stackhawk",
                description=description,
                asset=asset,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                recommendation=f"Review the StackHawk finding at {finding_url}",
                tags=[application, env] if env else [application],
                raw_data=raw_finding,
            ))

        return findings
