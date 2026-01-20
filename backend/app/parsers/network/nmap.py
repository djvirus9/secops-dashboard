import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class NmapParser(BaseParser):
    name = "nmap"
    display_name = "Nmap"
    category = ScannerCategory.NETWORK
    file_types = ["xml", "json"]
    description = "Nmap network discovery and security auditing"

    def can_parse(self, content: str) -> bool:
        return "nmap" in content.lower() or "nmaprun" in content.lower() or "<host" in content and "<port" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for host in root.findall(".//host"):
                    addr_el = host.find("address")
                    addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"
                    hostnames = host.find("hostnames")
                    hostname = ""
                    if hostnames is not None:
                        hn = hostnames.find("hostname")
                        hostname = hn.get("name", "") if hn is not None else ""
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            service = port.find("service")
                            service_name = service.get("name", "unknown") if service is not None else "unknown"
                            product = service.get("product", "") if service is not None else ""
                            version = service.get("version", "") if service is not None else ""
                            for script in port.findall(".//script"):
                                output = script.get("output", "")
                                if "VULNERABLE" in output.upper() or "vuln" in script.get("id", "").lower():
                                    findings.append(ParsedFinding(
                                        title=f"Vulnerability: {script.get('id', 'Unknown')}",
                                        description=output[:500],
                                        severity=self._infer_severity(output),
                                        tool=self.name,
                                        asset=f"{addr}:{port.get('portid', '')}",
                                        raw_data={"script": script.get("id"), "host": addr, "port": port.get("portid")}
                                    ))
                            findings.append(ParsedFinding(
                                title=f"Open Port: {port.get('portid', '')} ({service_name})",
                                description=f"Service: {product} {version}".strip() if product else f"Port {port.get('portid', '')} is open",
                                severity="info",
                                tool=self.name,
                                asset=f"{hostname or addr}:{port.get('portid', '')}",
                                raw_data={"host": addr, "hostname": hostname, "port": port.get("portid"), "service": service_name}
                            ))
            else:
                data = json.loads(content)
                for host in data.get("hosts", data.get("nmaprun", {}).get("host", [])):
                    if not isinstance(host, list):
                        host = [host]
                    for h in host:
                        addr = h.get("address", {}).get("addr", h.get("ip", "unknown"))
                        for port in h.get("ports", {}).get("port", []):
                            if port.get("state", {}).get("state") == "open":
                                findings.append(ParsedFinding(
                                    title=f"Open Port: {port.get('portid', '')}",
                                    description=f"Service: {port.get('service', {}).get('name', 'unknown')}",
                                    severity="info",
                                    tool=self.name,
                                    asset=f"{addr}:{port.get('portid', '')}",
                                    raw_data={"host": addr, **port}
                                ))
        except:
            pass
        return findings

    def _infer_severity(self, output: str) -> str:
        output_lower = output.lower()
        if "critical" in output_lower or "rce" in output_lower:
            return "critical"
        if "high" in output_lower or "vulnerable" in output_lower:
            return "high"
        if "medium" in output_lower:
            return "medium"
        return "low"
