import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class RiskReconParser(BaseParser):
    name = "risk_recon"
    display_name = "RiskRecon"
    category = ScannerCategory.CLOUD
    file_types = ["json"]
    description = "RiskRecon external attack surface management"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and data:
                first = data[0]
                return isinstance(first, dict) and "finding" in first and "domain_name" in first
            if isinstance(data, dict):
                return "findings" in data or "api_key" in data
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)

            # Normalise to a list of finding items
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("findings", [])
            else:
                return findings

            seen = {}
            for item in items:
                vendor = item.get("vendor", "")
                finding_name = item.get("finding", "")
                domain_name = item.get("domain_name", "")
                ip_address = item.get("ip_address", "")
                finding_id = item.get("finding_id", "")

                title = f"{vendor}: {finding_name} - {domain_name} ({ip_address})"

                description = (
                    f"**ID**: {finding_id}\n"
                    f"**Context**: {item.get('finding_context', '')}\n"
                    f"**Value**: {item.get('finding_data_value', '')}\n"
                    f"**Hosting Provider**: {item.get('hosting_provider', '')}\n"
                    f"**Host Name**: {item.get('host_name', '')}\n"
                    f"**Security Domain**: {item.get('security_domain', '')}\n"
                    f"**Security Criteria**: {item.get('security_criteria', '')}\n"
                    f"**Asset Value**: {item.get('asset_value', '')}\n"
                    f"**Country**: {item.get('country_name', '')}\n"
                    f"**Priority**: {item.get('priority', '')}\n"
                    f"**First Seen**: {item.get('first_seen', '')}\n"
                )

                sev = (item.get("severity") or "info").capitalize()
                asset = domain_name or ip_address or "unknown"

                dupe_key = finding_id or title
                if dupe_key in seen:
                    continue
                seen[dupe_key] = True

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    raw_data=item,
                ))
        except Exception:
            pass
        return findings
