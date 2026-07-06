import csv
import io
import xml.etree.ElementTree as ET
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

_INT_SEV = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
_STR_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "info", "info": "info"}


def _map_int_sev(val) -> str:
    try:
        return _INT_SEV.get(int(val), "info")
    except (TypeError, ValueError):
        return "info"


def _map_str_sev(val: str) -> str:
    return _STR_SEV.get((val or "").lower().strip(), "info")


@ParserRegistry.register
class TenableParser(BaseParser):
    name = "tenable"
    display_name = "Tenable"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["csv", "xml"]
    description = "Tenable.io / Nessus vulnerability scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        stripped = content.strip()
        if stripped.startswith("<?xml") or stripped.startswith("<NessusClientData"):
            try:
                root = ET.fromstring(stripped)
                return root.tag in ("NessusClientData_v2", "NessusClientData")
            except Exception:
                return False
        # CSV detection: look for Tenable-specific column headers
        try:
            first_line = stripped.splitlines()[0].lower()
            return "plugin id" in first_line or ("plugin" in first_line and "risk" in first_line and "host" in first_line)
        except Exception:
            return False

    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                plugin_name = row.get("Plugin", row.get("Name", row.get("Plugin Name", ""))).strip()
                host = row.get("Host", row.get("IP Address", "unknown")).strip()
                risk = row.get("Risk", row.get("Severity", "info")).strip()
                synopsis = row.get("Synopsis", "").strip()
                plugin_output = row.get("Plugin Output", "").strip()
                solution = row.get("Solution", "").strip()
                cve = row.get("CVE", "").strip()
                cvss = row.get("CVSS v3.0 Base Score", row.get("CVSS", "")).strip()
                product = row.get("Product", "").strip()
                version = row.get("Version", "").strip()

                if not plugin_name:
                    continue

                title = plugin_name
                if host and host != "unknown":
                    title = f"{plugin_name} on {host}"

                description = ""
                if synopsis:
                    description += f"**Synopsis**: {synopsis}\n\n"
                if plugin_output:
                    description += f"**Plugin Output**: {plugin_output}"

                sev_str = _map_str_sev(risk)

                cvss_score = None
                try:
                    cvss_score = float(cvss) if cvss else None
                except ValueError:
                    pass

                findings.append(ParsedFinding(
                    title=title,
                    severity=Severity.normalize(sev_str),
                    tool=self.name,
                    description=description,
                    asset=host,
                    recommendation=solution,
                    cve_id=cve if cve.upper().startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    raw_data=dict(row),
                ))
        except Exception:
            pass
        return findings

    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        findings = []
        try:
            root = ET.fromstring(content)
            for report in root.findall(".//Report"):
                for host in report.findall("ReportHost"):
                    host_name = host.get("name", "unknown")
                    for item in host.findall("ReportItem"):
                        plugin_name = item.get("pluginName", "").strip()
                        sev_int = item.get("severity", "0")
                        cve_elem = item.find("cve")
                        cve_id = cve_elem.text if cve_elem is not None else None
                        cvss_elem = item.find("cvss3_base_score")
                        if cvss_elem is None:
                            cvss_elem = item.find("cvss_base_score")
                        cvss_score = None
                        try:
                            cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else None
                        except ValueError:
                            pass

                        synopsis = (item.findtext("synopsis") or "").strip()
                        plugin_output = (item.findtext("plugin_output") or "").strip()
                        solution = (item.findtext("solution") or "").strip()

                        description = ""
                        if synopsis:
                            description += f"**Synopsis**: {synopsis}\n\n"
                        if plugin_output:
                            description += f"**Plugin Output**: {plugin_output}"

                        cwe_elem = item.find("cwe")
                        cwe_id = None
                        try:
                            cwe_id = int(cwe_elem.text) if cwe_elem is not None and cwe_elem.text else None
                        except ValueError:
                            pass

                        if not plugin_name:
                            continue

                        findings.append(ParsedFinding(
                            title=f"{plugin_name} on {host_name}",
                            severity=Severity.normalize(_map_int_sev(sev_int)),
                            tool=self.name,
                            description=description,
                            asset=host_name,
                            recommendation=solution,
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            cwe_id=cwe_id,
                            raw_data={"plugin_name": plugin_name, "host": host_name},
                        ))
        except Exception:
            pass
        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        stripped = content.strip()
        if stripped.startswith("<?xml") or stripped.startswith("<NessusClientData"):
            return self._parse_xml(stripped)
        return self._parse_csv(content)
