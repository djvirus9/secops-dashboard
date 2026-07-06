import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class WazuhParser(BaseParser):
    name = "wazuh"
    display_name = "Wazuh"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Wazuh SIEM vulnerability detection report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and ("data" in data or "hits" in data)
        except Exception:
            return False

    def _parse_v4_7(self, data: dict) -> List[ParsedFinding]:
        """Parse Wazuh v4.7 format: data.affected_items[]"""
        findings = []
        items = data.get("data", {}).get("affected_items", [])
        for item in items:
            vuln = item.get("vulnerability", {})
            cve_id = vuln.get("cve") or item.get("cve")
            severity = vuln.get("severity") or item.get("severity", "info")
            title = cve_id or vuln.get("title") or "Wazuh Vulnerability"
            description = vuln.get("description") or item.get("condition", "")
            package_name = item.get("name", "")
            package_version = item.get("version", "")
            agent_id = item.get("agent_id", "")

            if description == "Package unfixed":
                continue

            asset = package_name or agent_id or "unknown"
            if package_version:
                asset += f" {package_version}"

            cvss_score = None
            cvss = vuln.get("cvss", {})
            if isinstance(cvss, dict):
                try:
                    cvss_score = float(cvss.get("cvss3", {}).get("base_score", cvss.get("cvss2", {}).get("base_score", 0)) or 0) or None
                except (TypeError, ValueError):
                    pass

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(str(severity)),
                tool=self.name,
                description=description,
                asset=asset,
                cve_id=cve_id,
                cvss_score=cvss_score,
                raw_data=item,
            ))
        return findings

    def _parse_v4_8(self, data: dict) -> List[ParsedFinding]:
        """Parse Wazuh v4.8 format: hits.hits[]._source"""
        findings = []
        hits = data.get("hits", {}).get("hits", [])
        for hit in hits:
            source = hit.get("_source", {})
            vuln = source.get("vulnerability", {})
            cve_id = vuln.get("id") or source.get("vulnerability_id")
            severity = vuln.get("severity", "info")
            title = cve_id or vuln.get("reference") or "Wazuh Vulnerability"
            description = vuln.get("description", "")
            package = source.get("package", {})
            package_name = package.get("name", "")
            package_version = package.get("version", "")
            agent = source.get("agent", {})
            agent_name = agent.get("name", "")

            if description == "Package unfixed":
                continue

            asset = package_name or agent_name or "unknown"
            if package_version:
                asset += f" {package_version}"

            score = vuln.get("score", {})
            cvss_score = None
            try:
                base = score.get("base", 0)
                cvss_score = float(base) if base else None
            except (TypeError, ValueError):
                pass

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(str(severity)),
                tool=self.name,
                description=description,
                asset=asset,
                cve_id=cve_id,
                cvss_score=cvss_score,
                raw_data=source,
            ))
        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        try:
            data = json.loads(content)
            if not data:
                return []
            if data.get("data"):
                return self._parse_v4_7(data)
            if data.get("hits"):
                return self._parse_v4_8(data)
        except Exception:
            pass
        return []
