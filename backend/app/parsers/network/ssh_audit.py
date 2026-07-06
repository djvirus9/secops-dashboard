import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _cvss_to_severity(raw_value: str) -> str:
    try:
        val = float(raw_value)
    except (TypeError, ValueError):
        return "info"
    if val == 0:
        return "info"
    if val < 4.0:
        return "low"
    if val < 7.0:
        return "medium"
    if val < 9.0:
        return "high"
    return "critical"


@ParserRegistry.register
class SSHAuditParser(BaseParser):
    name = "ssh_audit"
    display_name = "SSH Audit"
    category = ScannerCategory.NETWORK
    file_types = ["json"]
    description = "SSH Audit SSH server security scanner (JSON)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "target" in data and "banner" in data
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        target_parts = data.get("target", "unknown:22").split(":", 1)
        host = target_parts[0]
        try:
            port = int(target_parts[1])
        except (IndexError, ValueError):
            port = 22

        banner_raw = data.get("banner", {}).get("raw", f"SSH server at {host}")
        asset = f"{host}:{port}"

        # CVE findings
        for cve in data.get("cves", []):
            cve_name = cve.get("name", "")
            cvss_v2 = cve.get("cvssv2", "0")
            severity_str = _cvss_to_severity(cvss_v2)
            desc_parts = [
                f"**CVE:** {cve_name}",
                f"**Description:** {cve.get('description', '')}",
                f"**Banner:** {banner_raw}",
                f"**CVSS v2:** {cvss_v2}",
            ]

            findings.append(ParsedFinding(
                title=f"{banner_raw}_{cve_name}",
                severity=Severity.normalize(severity_str),
                tool="ssh_audit",
                description="\n".join(desc_parts),
                asset=asset,
                cwe_id=None,
                cve_id=cve_name,
                cvss_score=float(cvss_v2) if cvss_v2 else None,
                recommendation="Patch or upgrade the SSH server to address this CVE.",
                raw_data=cve,
            ))

        # Key exchange algorithms
        for kex in data.get("kex", []):
            notes = kex.get("notes", {})
            if not notes:
                continue

            kex_name = kex.get("algorithm", "unknown")
            fail = notes.get("fail", "")
            warn = notes.get("warn", "")
            info = notes.get("info", "")

            if not fail and not warn:
                continue

            desc_parts = [f"**Algorithm:** {kex_name}"]
            if fail:
                desc_parts.append(f"**Failure:** {fail}")
            if warn:
                desc_parts.append(f"**Warning:** {warn}")
            if info:
                desc_parts.append(f"**Info:** {info}")

            severity_str = "high" if fail else "medium"

            findings.append(ParsedFinding(
                title=f"{banner_raw}_{kex_name}",
                severity=Severity.normalize(severity_str),
                tool="ssh_audit",
                description="\n".join(desc_parts),
                asset=asset,
                cwe_id=326,
                cve_id=None,
                cvss_score=None,
                recommendation="Disable weak or insecure key exchange algorithms in the SSH server configuration.",
                raw_data=kex,
            ))

        # Host key algorithms
        for key in data.get("key", []):
            notes = key.get("notes", {})
            if not notes:
                continue

            key_name = key.get("algorithm", "unknown")
            fail = notes.get("fail", "")
            warn = notes.get("warn", "")
            info = notes.get("info", "")

            if not fail and not warn:
                continue

            desc_parts = [f"**Algorithm:** {key_name}"]
            if key.get("keysize"):
                desc_parts.append(f"**Key Size:** {key['keysize']}")
            if fail:
                desc_parts.append(f"**Failure:** {fail}")
            if warn:
                desc_parts.append(f"**Warning:** {warn}")
            if info:
                desc_parts.append(f"**Info:** {info}")

            severity_str = "high" if fail else "medium"

            findings.append(ParsedFinding(
                title=f"{banner_raw}_{key_name}",
                severity=Severity.normalize(severity_str),
                tool="ssh_audit",
                description="\n".join(desc_parts),
                asset=asset,
                cwe_id=326,
                cve_id=None,
                cvss_score=None,
                recommendation="Replace weak host key algorithms with stronger alternatives.",
                raw_data=key,
            ))

        # MAC algorithms
        for mac in data.get("mac", []):
            notes = mac.get("notes", {})
            if not notes:
                continue

            mac_name = mac.get("algorithm", "unknown")
            fail = notes.get("fail", "")
            warn = notes.get("warn", "")
            info = notes.get("info", "")

            if not fail and not warn:
                continue

            desc_parts = [f"**Algorithm:** {mac_name}"]
            if fail:
                desc_parts.append(f"**Failure:** {fail}")
            if warn:
                desc_parts.append(f"**Warning:** {warn}")
            if info:
                desc_parts.append(f"**Info:** {info}")

            severity_str = "high" if fail else "medium"

            findings.append(ParsedFinding(
                title=f"{banner_raw}_{mac_name}",
                severity=Severity.normalize(severity_str),
                tool="ssh_audit",
                description="\n".join(desc_parts),
                asset=asset,
                cwe_id=326,
                cve_id=None,
                cvss_score=None,
                recommendation="Disable weak or insecure MAC algorithms in the SSH server configuration.",
                raw_data=mac,
            ))

        return findings
