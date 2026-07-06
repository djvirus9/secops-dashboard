import json
import re
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class AnchoreCTLPoliciesParser(BaseParser):
    name = "anchorectl_policies"
    display_name = "AnchoreCTL Policies"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "AnchoreCTL policy evaluation report"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            # New format: {"evaluations": [...], "imageDigest": ..., "policyId": ...}
            if isinstance(data, dict) and "evaluations" in data and "imageDigest" in data:
                return True
            # Legacy list format: [{"detail": [...], "digest": ..., "policyId": ...}]
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                return isinstance(first, dict) and ("detail" in first or "details" in first) and "policyId" in first
            return False
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []

        # Normalize new format to list format
        if isinstance(data, dict) and "evaluations" in data:
            data = self._normalize_new_format(data)

        if not isinstance(data, list):
            return findings

        for image in data:
            if not isinstance(image, dict):
                continue

            details = image.get("detail") or image.get("details") or []
            if not isinstance(details, list):
                continue

            for result in details:
                try:
                    finding = self._process_detail(result, image)
                    if finding:
                        findings.append(finding)
                except Exception:
                    continue

        return findings

    def _normalize_new_format(self, data: dict) -> list:
        processed = []
        for evaluation in data.get("evaluations", []):
            if evaluation.get("numberOfFindings", 0) > 0 and evaluation.get("details"):
                processed.append({
                    "detail": evaluation.get("details", []),
                    "digest": data.get("imageDigest", ""),
                    "finalAction": evaluation.get("finalAction", ""),
                    "lastEvaluation": evaluation.get("evaluationTime", ""),
                    "policyId": data.get("policyId", ""),
                    "status": evaluation.get("status", ""),
                    "tag": data.get("evaluatedTag", ""),
                })
        return processed

    def _process_detail(self, result: dict, image: dict) -> Optional[ParsedFinding]:
        gate = result.get("gate", "unknown")
        description_text = result.get("description", "No description provided")
        policy_id = result.get("policyId", image.get("policyId", "unknown"))
        status = result.get("status", "unknown")
        image_name = result.get("tag", image.get("tag", "unknown:latest"))
        trigger_id = result.get("triggerId", "unknown")

        # Split image name into repo + tag
        if ":" in image_name:
            repo, tag = image_name.split(":", 1)
        else:
            repo = image_name
            tag = "latest"

        severity, active = self._get_severity(status, description_text)
        vuln_id = self._extract_vulnerability_id(trigger_id)

        title = f"{policy_id} - gate|{gate} - trigger|{trigger_id}"

        file_path = self._search_filepath(description_text)

        finding = ParsedFinding(
            title=title,
            severity=Severity.normalize(severity),
            tool="anchorectl_policies",
            description=description_text,
            asset=repo,
            file_path=file_path if file_path else None,
            cve_id=vuln_id if vuln_id and vuln_id.startswith("CVE-") else None,
            recommendation="",
            references=[f"Policy ID: {policy_id}", f"Trigger ID: {trigger_id}"],
            tags=["anchorectl", "policy", gate, tag],
            raw_data=result,
        )
        return finding

    def _get_severity(self, status: str, description: str) -> tuple:
        gate_action_map = {
            "stop": ("critical", True),
            "warn": ("medium", True),
        }

        parsed = description.split()[0] if description.strip() else ""
        valid_severities = {"LOW", "INFO", "UNKNOWN", "CRITICAL", "MEDIUM"}

        if parsed in valid_severities:
            if parsed == "UNKNOWN":
                severity = "info"
            elif status != "go":
                severity = parsed.lower()
            else:
                severity = "info"
            active = status != "go"
            return severity, active

        return gate_action_map.get(status, ("low", True))

    def _extract_vulnerability_id(self, trigger_id: str) -> Optional[str]:
        try:
            vuln_id, _ = trigger_id.split("+", 1)
            if vuln_id.startswith("CVE"):
                return vuln_id
        except ValueError:
            pass
        return None

    def _search_filepath(self, text: str) -> str:
        match = re.search(r" (/[^/ ]*)+/?", text)
        if match:
            try:
                return match.group(0).strip()
            except IndexError:
                pass
        return ""
