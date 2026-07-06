import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


def _map_severity(sev: str) -> str:
    mapping = {
        "critical": "critical",
        "important": "high",
        "moderate": "medium",
        "low": "low",
    }
    return mapping.get((sev or "").lower().strip(), "low")


@ParserRegistry.register
class RedHatSatelliteParser(BaseParser):
    name = "redhatsatellite"
    display_name = "Red Hat Satellite"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Red Hat Satellite patch and errata management"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and "results" in data
                and isinstance(data["results"], list)
                and len(data["results"]) > 0
                and "errata_id" in data["results"][0]
            )
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for result in data.get("results", []):
                title = result.get("title") or result.get("name") or "Unknown Errata"
                sev = _map_severity(result.get("severity", ""))
                description = result.get("description", "") + "\n"

                errata_id = result.get("errata_id")
                summary = result.get("summary", "")
                if summary:
                    description += f"\n**Summary**: {summary}"
                packages = result.get("packages", [])
                if packages:
                    description += f"\n**Packages**: {', '.join(packages)}"
                hosts_available = result.get("hosts_available_count")
                if hosts_available is not None:
                    description += f"\n**Hosts Available**: {hosts_available}"

                cve_ids = []
                if errata_id:
                    cve_ids.append(errata_id)
                for cve in result.get("cves", []):
                    cve_id = cve.get("cve_id")
                    if cve_id:
                        cve_ids.append(cve_id)

                cve = cve_ids[0] if cve_ids else None

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev),
                    tool=self.name,
                    description=description.strip(),
                    asset="unknown",
                    recommendation=result.get("solution", ""),
                    cve_id=cve,
                    raw_data=result,
                ))
        except Exception:
            pass
        return findings
