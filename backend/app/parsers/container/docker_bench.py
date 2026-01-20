import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class DockerBenchParser(BaseParser):
    name = "docker-bench"
    display_name = "Docker Bench for Security"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Docker CIS benchmark security scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return "tests" in data and any("docker" in str(t).lower() for t in data.get("tests", [])[:3])
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        for test in data.get("tests", []):
            section = test.get("section", "")
            
            for result in test.get("results", []):
                status = result.get("result", "").upper()
                if status in ["PASS", "INFO"]:
                    continue
                
                severity = Severity.MEDIUM
                if status == "WARN":
                    severity = Severity.MEDIUM
                elif status == "NOTE":
                    severity = Severity.LOW
                
                finding = ParsedFinding(
                    title=f"{result.get('id', section)}: {result.get('desc', 'Docker Benchmark Check')}",
                    severity=severity,
                    tool="docker-bench",
                    description=result.get("desc", ""),
                    asset=result.get("details", "docker-host"),
                    recommendation=result.get("remediation", ""),
                    tags=["docker", "cis-benchmark", section],
                    raw_data=result,
                )
                findings.append(finding)
        
        return findings
