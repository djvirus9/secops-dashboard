import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _grade_to_severity(grade: str) -> str:
    if "A" in grade:
        return "info"
    if "B" in grade:
        return "medium"
    if "C" in grade:
        return "high"
    return "critical"


@ParserRegistry.register
class SSLLabsParser(BaseParser):
    name = "ssl_labs"
    display_name = "SSL Labs"
    category = ScannerCategory.NETWORK
    file_types = ["json"]
    description = "SSL Labs TLS/SSL scanner (JSON)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return isinstance(first, dict) and "host" in first and "endpoints" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        seen = set()
        for host_entry in data:
            host_name = host_entry.get("host", "unknown")
            port = host_entry.get("port", 443)
            protocol = host_entry.get("protocol", "https")

            for endpoint in host_entry.get("endpoints", []):
                grade = endpoint.get("grade", "")
                if not grade:
                    continue

                ip_address = endpoint.get("ipAddress", "")
                title = f"TLS Grade '{grade}' for {host_name}"
                severity_str = _grade_to_severity(grade)

                # Build description
                details = endpoint.get("details", {})
                desc_parts = [f"**Host:** {host_name}", f"**IP:** {ip_address}", f"**Grade:** {grade}"]

                # Certificate info
                cert = details.get("cert", {})
                if cert:
                    desc_parts.append(f"**Certificate Subject:** {cert.get('subject', '')}")
                    desc_parts.append(f"**Issuer:** {cert.get('issuerSubject', '')}")
                    desc_parts.append(f"**Signature Algorithm:** {cert.get('sigAlg', '')}")
                else:
                    for c in host_entry.get("certs", []):
                        desc_parts.append(f"**Certificate Subject:** {c.get('subject', '')}")
                        desc_parts.append(f"**Issuer:** {c.get('issuerSubject', '')}")
                        break

                # Protocols
                protocols = details.get("protocols", [])
                if protocols:
                    proto_strs = [f"{p.get('name', '')} {p.get('version', '')}" for p in protocols]
                    desc_parts.append("**Protocols:** " + ", ".join(proto_strs))

                # Known vulnerabilities
                for flag in ("heartbleed", "poodle", "poodleTls", "freak", "vulnBeast"):
                    val = details.get(flag)
                    if val:
                        desc_parts.append(f"**{flag}:** {val}")

                # HSTS
                if details.get("hstsPolicy", {}).get("status") == "absent":
                    desc_parts.append("**HSTS:** Not configured")

                dedup_key = f"{host_name}:{grade}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                asset = f"{protocol}://{host_name}:{port}" if port else f"{protocol}://{host_name}"

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(severity_str),
                    tool="ssl_labs",
                    description="\n".join(desc_parts),
                    asset=asset,
                    cwe_id=310,
                    cve_id=None,
                    cvss_score=None,
                    recommendation="Review SSL/TLS configuration and upgrade to achieve grade A or better.",
                    raw_data=endpoint,
                ))

        return findings
