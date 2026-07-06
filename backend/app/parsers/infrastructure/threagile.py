import json
from typing import List, Optional
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

RISK_TO_CWE = {
    "accidental-secret-leak": 200,
    "code-backdooring": 912,
    "container-baseimage-backdooring": 912,
    "container-platform-escape": 1008,
    "cross-site-request-forgery": 352,
    "cross-site-scripting": 79,
    "dos-risky-access-across-trust-boundary": 400,
    "ldap-injection": 90,
    "missing-authentication-second-factor": 308,
    "missing-authentication": 306,
    "missing-file-validation": 434,
    "missing-hardening": 16,
    "missing-vault": 522,
    "path-traversal": 22,
    "search-query-injection": 74,
    "server-side-request-forgery": 918,
    "sql-injection-rule": 89,
    "unencrypted-asset": 311,
    "unencrypted-communication": 319,
    "untrusted-deserialization": 502,
    "xml-external-entity": 611,
}


@ParserRegistry.register
class ThreagileParser(BaseParser):
    name = "threagile"
    display_name = "Threagile"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Threagile threat modeling risks report (JSON)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return isinstance(first, dict) and "category" in first and "synthetic_id" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            if not isinstance(data, list):
                return findings
            for item in data:
                category = item.get("category", "unknown")
                title_text = item.get("title", category)
                raw_sev = item.get("severity", "info")
                if str(raw_sev).lower() == "elevated":
                    raw_sev = "high"
                sev = Severity.normalize(str(raw_sev))

                description = title_text
                impact = item.get("exploitation_impact", "")
                if impact:
                    description += f"\n\n**Impact**: {impact}"

                component = (
                    item.get("most_relevant_technical_asset")
                    or item.get("most_relevant_trust_boundary")
                    or item.get("most_relevant_data_asset")
                    or "unknown"
                )

                cwe_id = RISK_TO_CWE.get(category)

                findings.append(ParsedFinding(
                    title=category,
                    severity=sev,
                    tool=self.name,
                    description=description,
                    asset=component,
                    cwe_id=cwe_id,
                    raw_data=item,
                ))
        except Exception:
            pass
        return findings
