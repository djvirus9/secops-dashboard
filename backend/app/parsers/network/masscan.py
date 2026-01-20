import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class MasscanParser(BaseParser):
    name = "masscan"
    display_name = "Masscan"
    category = ScannerCategory.NETWORK
    file_types = ["json"]
    description = "Masscan high-speed port scanner"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "ip" in data[0] and "ports" in data[0]
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for host in data:
                ip = host.get("ip", "unknown")
                for port in host.get("ports", []):
                    findings.append(ParsedFinding(
                        title=f"Open Port: {port.get('port', '')} ({port.get('proto', 'tcp')})",
                        description=f"Port {port.get('port', '')} is open on {ip}",
                        severity="info",
                        tool=self.name,
                        asset=f"{ip}:{port.get('port', '')}",
                        raw_data={"ip": ip, **port}
                    ))
        except:
            pass
        return findings
