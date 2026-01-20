import json
import xml.etree.ElementTree as ET
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class OpenVASParser(BaseParser):
    name = "openvas"
    display_name = "OpenVAS"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["xml", "json"]
    description = "OpenVAS/Greenbone vulnerability scanner"

    def can_parse(self, content: str) -> bool:
        return "OpenVAS" in content or "openvas" in content.lower() or "Greenbone" in content or "<report" in content and "<result" in content

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("<"):
                root = ET.fromstring(content)
                for result in root.findall(".//result"):
                    nvt = result.find("nvt")
                    threat = result.findtext("threat", "medium")
                    if threat.lower() not in ["log", "false positive"]:
                        nvt_name = nvt.findtext("name", "OpenVAS Finding") if nvt is not None else "OpenVAS Finding"
                        host_el = result.find("host")
                        host = host_el.text if host_el is not None else "unknown"
                        findings.append(ParsedFinding(
                            title=nvt_name,
                            description=result.findtext("description", ""),
                            severity=self._map_severity(threat),
                            tool=self.name,
                            asset=f"{host}:{result.findtext('port', '')}",
                            cve=self._extract_cve(nvt),
                            cvss_score=self._extract_cvss(nvt),
                            raw_data={"nvt_oid": nvt.get("oid") if nvt is not None else None}
                        ))
            else:
                data = json.loads(content)
                for result in data.get("results", []):
                    findings.append(ParsedFinding(
                        title=result.get("name", "OpenVAS Finding"),
                        description=result.get("description", ""),
                        severity=self._map_severity(result.get("threat", result.get("severity", "medium"))),
                        tool=self.name,
                        asset=result.get("host", "unknown"),
                        cve=result.get("cve"),
                        cvss_score=result.get("cvss_base"),
                        raw_data=result
                    ))
        except:
            pass
        return findings

    def _extract_cve(self, nvt) -> str | None:
        if nvt is None:
            return None
        refs = nvt.find("refs")
        if refs is not None:
            for ref in refs.findall("ref"):
                if ref.get("type") == "cve":
                    return ref.get("id")
        return nvt.findtext("cve")

    def _extract_cvss(self, nvt) -> float | None:
        if nvt is None:
            return None
        try:
            cvss_el = nvt.find("cvss_base")
            return float(cvss_el.text) if cvss_el is not None else None
        except:
            return None

    def _map_severity(self, threat: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "log": "info", "alarm": "critical"}
        return mapping.get(threat.lower(), "medium")
