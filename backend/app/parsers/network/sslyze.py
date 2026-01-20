import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class SSLyzeParser(BaseParser):
    name = "sslyze"
    display_name = "SSLyze"
    category = ScannerCategory.NETWORK
    file_types = ["json"]
    description = "SSLyze SSL/TLS configuration analyzer"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "server_scan_results" in data or "sslyze_version" in data or "server_info" in str(data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for result in data.get("server_scan_results", [data]):
                server = result.get("server_info", {}).get("server_location", {})
                hostname = server.get("hostname", result.get("server_info", {}).get("hostname", "unknown"))
                port = server.get("port", 443)
                scan_commands = result.get("scan_commands_results", result.get("scan_result", {}))
                if scan_commands.get("ssl_2_0_cipher_suites", {}).get("accepted_cipher_suites"):
                    findings.append(ParsedFinding(
                        title="SSL 2.0 Enabled",
                        description="Server supports SSLv2 which is insecure and deprecated",
                        severity="critical",
                        tool=self.name,
                        asset=f"{hostname}:{port}",
                        raw_data={"vulnerability": "ssl2_enabled"}
                    ))
                if scan_commands.get("ssl_3_0_cipher_suites", {}).get("accepted_cipher_suites"):
                    findings.append(ParsedFinding(
                        title="SSL 3.0 Enabled",
                        description="Server supports SSLv3 which is vulnerable to POODLE",
                        severity="high",
                        tool=self.name,
                        asset=f"{hostname}:{port}",
                        cve="CVE-2014-3566",
                        raw_data={"vulnerability": "ssl3_enabled"}
                    ))
                heartbleed = scan_commands.get("heartbleed", {})
                if heartbleed.get("is_vulnerable_to_heartbleed"):
                    findings.append(ParsedFinding(
                        title="Heartbleed Vulnerability",
                        description="Server is vulnerable to Heartbleed (CVE-2014-0160)",
                        severity="critical",
                        tool=self.name,
                        asset=f"{hostname}:{port}",
                        cve="CVE-2014-0160",
                        raw_data={"vulnerability": "heartbleed"}
                    ))
                robot = scan_commands.get("robot", {})
                if robot.get("robot_result") and "VULNERABLE" in str(robot.get("robot_result", "")).upper():
                    findings.append(ParsedFinding(
                        title="ROBOT Vulnerability",
                        description="Server is vulnerable to ROBOT attack",
                        severity="high",
                        tool=self.name,
                        asset=f"{hostname}:{port}",
                        raw_data={"vulnerability": "robot"}
                    ))
                cert_info = scan_commands.get("certificate_info", {})
                if cert_info.get("certificate_deployments"):
                    for deploy in cert_info.get("certificate_deployments", []):
                        validations = deploy.get("path_validation_results", [])
                        for val in validations:
                            if not val.get("was_validation_successful"):
                                findings.append(ParsedFinding(
                                    title="Certificate Validation Failed",
                                    description=f"Certificate validation failed: {val.get('openssl_error_string', 'unknown error')}",
                                    severity="medium",
                                    tool=self.name,
                                    asset=f"{hostname}:{port}",
                                    raw_data=val
                                ))
        except:
            pass
        return findings
