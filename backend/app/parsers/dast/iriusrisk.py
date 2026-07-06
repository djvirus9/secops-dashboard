import csv
import io
import re
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

SEVERITY_MAP = {
    "very low": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@ParserRegistry.register
class IriusRiskParser(BaseParser):
    name = "iriusrisk"
    display_name = "IriusRisk"
    category = ScannerCategory.DAST
    file_types = ["csv"]
    description = "IriusRisk threat modeling tool CSV export"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            reader = csv.DictReader(io.StringIO(content))
            fields = set(reader.fieldnames or [])
            # IriusRisk CSV has these specific columns
            required = {"Threat", "Component", "Current Risk"}
            return required.issubset(fields)
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content))

        for row in reader:
            threat = (row.get("Threat") or "").strip()
            component = (row.get("Component") or "").strip()
            use_case = (row.get("Use case") or "").strip()
            source = (row.get("Source") or "").strip()
            risk_response = (row.get("Risk Response") or "").strip()
            inherent_risk = (row.get("Inherent Risk") or "").strip()
            current_risk = (row.get("Current Risk") or "").strip()
            projected_risk = (row.get("Projected Risk") or "").strip()
            countermeasure_progress = (row.get("Countermeasure progress") or "").strip()
            weakness_tests = (row.get("Weakness tests") or "").strip()
            countermeasure_tests = (row.get("Countermeasure tests") or "").strip()
            owner = (row.get("Owner") or "").strip()
            mitre_reference = (row.get("MITRE reference") or "").strip()
            stride_lm = (row.get("STRIDE-LM") or "").strip()

            if not threat:
                continue

            title = threat[:497] + "..." if len(threat) > 500 else threat
            severity_str = SEVERITY_MAP.get(current_risk.lower(), "info")

            description_parts = [
                f"**Threat:** {threat}",
                f"**Component:** {component}",
            ]
            if use_case:
                description_parts.append(f"**Use Case:** {use_case}")
            if source:
                description_parts.append(f"**Source:** {source}")
            description_parts += [
                f"**Inherent Risk:** {inherent_risk}",
                f"**Current Risk:** {current_risk}",
                f"**Projected Risk:** {projected_risk}",
            ]
            if countermeasure_progress:
                description_parts.append(f"**Countermeasure Progress:** {countermeasure_progress}")
            if weakness_tests:
                description_parts.append(f"**Weakness Tests:** {weakness_tests}")
            if countermeasure_tests:
                description_parts.append(f"**Countermeasure Tests:** {countermeasure_tests}")
            if owner:
                description_parts.append(f"**Owner:** {owner}")
            if stride_lm:
                description_parts.append(f"**STRIDE-LM:** {stride_lm}")

            cwe_id = None
            references = []
            if mitre_reference:
                cwe_match = re.match(r"CWE-(\d+)", mitre_reference)
                if cwe_match:
                    cwe_id = int(cwe_match.group(1))
                else:
                    references.append(mitre_reference)

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="iriusrisk",
                description="\n".join(description_parts),
                asset=component or "unknown",
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation=risk_response,
                references=references,
                tags=[stride_lm] if stride_lm else [],
                raw_data=dict(row),
            ))

        return findings
