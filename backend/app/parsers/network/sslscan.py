import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SSLScanParser(BaseParser):
    name = "sslscan"
    display_name = "SSLScan"
    category = ScannerCategory.NETWORK
    file_types = ["xml"]
    description = "SSLScan SSL/TLS configuration scanner (XML)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            root = ET.fromstring(content)
            return "document" in root.tag.lower()
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        root = ET.fromstring(content)

        seen = set()
        for ssltest in root:
            host = ssltest.get("host", "unknown")
            port_str = ssltest.get("port", "443")
            try:
                port = int(port_str)
            except ValueError:
                port = 443

            asset = f"{host}:{port}"

            for target in ssltest:
                tag = target.tag
                title = ""
                description = ""

                if tag == "heartbleed" and target.get("vulnerable") == "1":
                    ssl_version = target.get("sslversion", "")
                    title = f"Heartbleed | {ssl_version}"
                    description = (
                        f"**Heartbleed Vulnerability Detected**\n\n"
                        f"**SSL Version:** {ssl_version}\n\n"
                        "The server is vulnerable to the Heartbleed attack (CVE-2014-0160)."
                    )

                elif tag == "cipher":
                    strength = target.get("strength", "")
                    if strength not in ("acceptable", "strong"):
                        ssl_version = target.get("sslversion", "")
                        cipher = target.get("cipher", "")
                        status = target.get("status", "")
                        title = f"Weak cipher | {ssl_version}"
                        description = (
                            f"**Cipher:** {cipher}\n\n"
                            f"**Status:** {status}\n\n"
                            f"**Strength:** {strength}\n\n"
                            f"**SSL Version:** {ssl_version}"
                        )

                if title:
                    dedup_key = f"{description}|{title}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    findings.append(ParsedFinding(
                        title=title,
                        severity=Severity.INFO,
                        tool="sslscan",
                        description=description,
                        asset=asset,
                        cwe_id=326,
                        cve_id="CVE-2014-0160" if "heartbleed" in tag.lower() else None,
                        cvss_score=None,
                        recommendation="Disable weak ciphers and upgrade to TLS 1.2/1.3 with strong cipher suites.",
                        raw_data=target.attrib,
                    ))

        return findings
