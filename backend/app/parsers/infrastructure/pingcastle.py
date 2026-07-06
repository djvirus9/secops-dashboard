import re
import xml.etree.ElementTree as ET
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _safe_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def _points_to_severity(points: int) -> str:
    if points <= 0:
        return "info"
    if points <= 5:
        return "low"
    if points <= 10:
        return "medium"
    if points <= 15:
        return "high"
    return "critical"


@ParserRegistry.register
class PingCastleParser(BaseParser):
    name = "pingcastle"
    display_name = "PingCastle"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["xml"]
    description = "PingCastle Active Directory security auditor"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            root = ET.fromstring(content)
            return root.tag == "HealthcheckData" or root.find("RiskRules") is not None
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        seen = {}
        try:
            root = ET.fromstring(content)
            domain_fqdn = root.findtext("DomainFQDN") or ""

            for rr in root.findall("RiskRules/HealthcheckRiskRule"):
                points = _safe_int(rr.findtext("Points"))
                category = rr.findtext("Category") or ""
                model = rr.findtext("Model") or ""
                risk_id = rr.findtext("RiskId") or ""
                rationale = rr.findtext("Rationale") or ""

                sev_str = _points_to_severity(points)
                title = f"[PingCastle] {risk_id} ({category}/{model})"

                description_lines = [
                    "### PingCastle Risk Rule",
                    f"**Domain**: `{domain_fqdn}`",
                    f"**RiskId**: `{risk_id}`",
                    f"**Category/Model**: `{category}` / `{model}`",
                    f"**Points**: `{points}`",
                ]
                if rationale:
                    description_lines.append(f"**Rationale**: {rationale}")
                description = "\n".join(description_lines)

                cves = CVE_REGEX.findall(rationale)
                cve_id = cves[0] if cves else None

                if risk_id in seen:
                    seen[risk_id].description += "\n\n---\n\n" + description
                else:
                    f = ParsedFinding(
                        title=title,
                        severity=Severity.normalize(sev_str),
                        tool=self.name,
                        description=description,
                        asset=domain_fqdn or "unknown",
                        cve_id=cve_id,
                        raw_data={
                            "risk_id": risk_id,
                            "category": category,
                            "model": model,
                            "points": points,
                            "rationale": rationale,
                        },
                    )
                    seen[risk_id] = f
                    findings.append(f)
        except Exception:
            pass
        return findings
