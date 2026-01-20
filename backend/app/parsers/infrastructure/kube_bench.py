import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class KubeBenchParser(BaseParser):
    name = "kube_bench"
    display_name = "kube-bench"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "CIS Kubernetes Benchmark checks"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "Controls" in data or "Totals" in data or ("tests" in str(data) and "results" in str(data))
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            controls = data.get("Controls", [])
            for control in controls:
                for test in control.get("tests", []):
                    for result in test.get("results", []):
                        if result.get("status") in ["FAIL", "WARN"]:
                            findings.append(ParsedFinding(
                                title=f"[{result.get('test_number', '')}] {result.get('test_desc', 'kube-bench Finding')}",
                                description=result.get("remediation", result.get("reason", "")),
                                severity=self._map_severity(result.get("status", "medium"), result.get("scored", True)),
                                tool=self.name,
                                asset=control.get("text", control.get("id", "kubernetes")),
                                raw_data=result
                            ))
        except:
            pass
        return findings

    def _map_severity(self, status: str, scored: bool) -> str:
        if status == "FAIL":
            return "high" if scored else "medium"
        return "low"
