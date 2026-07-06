import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

_VULNERS_SEVERITY = {
    0: "info",
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


@ParserRegistry.register
class ApiVulnersParser(BaseParser):
    name = "api_vulners"
    display_name = "Vulners API"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Vulners.com vulnerability scanner API report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and "data" in data
                and isinstance(data["data"], dict)
                and "report" in data["data"]
            )
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            outer = json.loads(content)
            data = outer.get("data", {})
            report = data.get("report", [])
            vulns = data.get("vulns", {})

            for component in report:
                vuln_id = component.get("vulnID", "")
                vuln = vulns.get(vuln_id, {})
                title = component.get("title") or vuln_id
                severity_int = component.get("severity", 0)
                sev_str = _VULNERS_SEVERITY.get(severity_int, "info")

                agent_ip = component.get("agentip", "")
                agent_fqdn = component.get("agentfqdn", "")
                asset = agent_fqdn if agent_fqdn and agent_fqdn != "unknown" else agent_ip or "unknown"

                description = vuln.get("description", title)

                # References
                family = component.get("family", "")
                references = []
                if family and vuln_id:
                    references.append(f"https://vulners.com/{family}/{vuln_id}")
                for cve in vuln.get("cvelist", []):
                    references.append(f"https://vulners.com/cve/{cve}")
                for ref in vuln.get("references", []):
                    references.append(str(ref))

                cve_list = vuln.get("cvelist", [])
                cve_id = cve_list[0] if cve_list else None

                cvss_score = None
                cvss3 = vuln.get("cvss3", {})
                if isinstance(cvss3, dict):
                    cvss_vec = cvss3.get("cvssV3", {})
                    if isinstance(cvss_vec, dict):
                        try:
                            cvss_score = float(cvss_vec.get("baseScore", 0) or 0) or None
                        except (TypeError, ValueError):
                            pass

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev_str),
                    tool=self.name,
                    description=description,
                    asset=asset,
                    recommendation=component.get("cumulativeFix", ""),
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    references=references,
                    raw_data=component,
                ))
        except Exception:
            pass
        return findings
