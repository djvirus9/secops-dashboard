import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

TRIVY_OPERATOR_SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

TRIVY_OPERATOR_CRD_KEYS = {
    "clustercompliancereports.aquasecurity.github.io",
    "clusterconfigauditreports.aquasecurity.github.io",
    "clusterinfraassessmentreports.aquasecurity.github.io",
    "clusterrbacassessmentreports.aquasecurity.github.io",
    "configauditreports.aquasecurity.github.io",
    "exposedsecretreports.aquasecurity.github.io",
    "infraassessmentreports.aquasecurity.github.io",
    "rbacassessmentreports.aquasecurity.github.io",
    "vulnerabilityreports.aquasecurity.github.io",
}


@ParserRegistry.register
class TrivyOperatorParser(BaseParser):
    name = "trivy_operator"
    display_name = "Trivy Operator"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Trivy Operator Kubernetes VulnerabilityReport CRD scanner"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list):
                if len(data) == 0:
                    return False
                first = data[0]
                return cls._is_trivy_operator_item(first)
            if isinstance(data, dict):
                # Trivy operator export format: top-level keys are CRD names
                if TRIVY_OPERATOR_CRD_KEYS & set(data.keys()):
                    return True
                return cls._is_trivy_operator_item(data)
            return False
        except Exception:
            return False

    @classmethod
    def _is_trivy_operator_item(cls, item: dict) -> bool:
        if not isinstance(item, dict):
            return False
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            return False
        labels = metadata.get("labels", {})
        # Trivy operator labels contain trivy-operator prefix
        return any("trivy-operator" in str(k) for k in labels.keys())

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []

        if isinstance(data, list):
            for item in data:
                findings.extend(self._process_item(item))
        elif isinstance(data, dict):
            if TRIVY_OPERATOR_CRD_KEYS & set(data.keys()):
                for key in data.keys():
                    if key not in {"clustersbomreports.aquasecurity.github.io", "sbomreports.aquasecurity.github.io"}:
                        for item in data[key]:
                            findings.extend(self._process_item(item))
            else:
                findings.extend(self._process_item(data))

        return findings

    def _process_item(self, data: dict) -> List[ParsedFinding]:
        findings = []
        if not isinstance(data, dict):
            return findings

        metadata = data.get("metadata", {})
        if not metadata:
            return findings
        labels = metadata.get("labels", {})
        if not labels:
            return findings

        resource_namespace = labels.get("trivy-operator.resource.namespace", "")
        resource_kind = labels.get("trivy-operator.resource.kind", "")
        resource_name = labels.get("trivy-operator.resource.name", "")
        container_name = labels.get("trivy-operator.container.name", "")
        service = f"{resource_namespace}/{resource_kind}/{resource_name}"
        if container_name:
            service = f"{service}/{container_name}"

        report = data.get("report", {})
        if report:
            vulns = report.get("vulnerabilities", [])
            for vuln in vulns:
                finding = self._vuln_to_finding(vuln, labels, service, container_name, resource_kind, resource_name, resource_namespace)
                if finding:
                    findings.append(finding)

            checks = report.get("checks", [])
            for check in checks:
                finding = self._check_to_finding(check, labels, service)
                if finding:
                    findings.append(finding)

            secrets = report.get("secrets", [])
            for secret in secrets:
                finding = self._secret_to_finding(secret, labels, service)
                if finding:
                    findings.append(finding)

        # Compliance reports
        status = data.get("status", {})
        if status:
            detail_report = status.get("detailReport", {})
            for ctrl in detail_report.get("controls", []):
                finding = self._compliance_check_to_finding(ctrl, service)
                if finding:
                    findings.append(finding)

        return findings

    def _vuln_to_finding(self, vuln: dict, labels: dict, service: str, container_name: str, resource_kind: str, resource_name: str, resource_namespace: str) -> Optional[ParsedFinding]:
        vuln_id = vuln.get("vulnerabilityID", "Unknown")
        severity_raw = vuln.get("severity", "UNKNOWN")
        severity = TRIVY_OPERATOR_SEVERITIES.get(severity_raw, "info")

        package_name = vuln.get("resource", "unknown")
        package_version = vuln.get("installedVersion", "")
        fixed_version = vuln.get("fixedVersion", "")
        primary_link = vuln.get("primaryLink", "")
        cvss_score = vuln.get("score")

        title = vuln.get("title", "")
        description = f"{title}\n**Fixed version:** {fixed_version}\n"
        description += f"\n**container.name:** {container_name}"
        description += f"\n**resource.kind:** {resource_kind}"
        description += f"\n**resource.name:** {resource_name}"
        description += f"\n**resource.namespace:** {resource_namespace}"

        finding_title = f"{vuln_id} {package_name} {package_version}"

        package_path = vuln.get("packagePath")
        target = vuln.get("target")
        target_class = vuln.get("class")
        file_path = None
        if target_class in ("os-pkgs", "lang-pkgs"):
            file_path = package_path or target

        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except Exception:
            cvss_score = None

        return ParsedFinding(
            title=finding_title,
            severity=Severity.normalize(severity),
            tool="trivy_operator",
            description=description,
            asset=service or package_name,
            file_path=file_path,
            cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
            cvss_score=cvss_score,
            recommendation=f"Update to {fixed_version}" if fixed_version else "",
            references=[primary_link] if primary_link else [],
            tags=["trivy-operator", "container", resource_namespace] if resource_namespace else ["trivy-operator", "container"],
            raw_data=vuln,
        )

    def _check_to_finding(self, check: dict, labels: dict, service: str) -> Optional[ParsedFinding]:
        check_id = check.get("checkID", check.get("id", "Unknown"))
        title = check.get("title", check_id)
        severity_raw = check.get("severity", "UNKNOWN")
        severity = TRIVY_OPERATOR_SEVERITIES.get(severity_raw, "info")
        description = check.get("description", "")
        success = check.get("success", True)

        if success:
            return None  # Only report failed checks

        return ParsedFinding(
            title=f"{check_id}: {title}",
            severity=Severity.normalize(severity),
            tool="trivy_operator",
            description=description,
            asset=service or "unknown",
            recommendation=check.get("remediation", ""),
            tags=["trivy-operator", "config-audit"],
            raw_data=check,
        )

    def _secret_to_finding(self, secret: dict, labels: dict, service: str) -> Optional[ParsedFinding]:
        rule_id = secret.get("ruleID", "Unknown")
        title = secret.get("title", rule_id)
        severity_raw = secret.get("severity", "UNKNOWN")
        severity = TRIVY_OPERATOR_SEVERITIES.get(severity_raw, "info")

        return ParsedFinding(
            title=f"{rule_id}: {title}",
            severity=Severity.normalize(severity),
            tool="trivy_operator",
            description=secret.get("category", ""),
            asset=service or "unknown",
            file_path=secret.get("target"),
            tags=["trivy-operator", "secrets"],
            raw_data=secret,
        )

    def _compliance_check_to_finding(self, ctrl: dict, service: str) -> Optional[ParsedFinding]:
        ctrl_id = ctrl.get("id", "Unknown")
        title = ctrl.get("name", ctrl_id)
        severity_raw = ctrl.get("severity", "UNKNOWN")
        severity = TRIVY_OPERATOR_SEVERITIES.get(severity_raw.upper() if severity_raw else "UNKNOWN", "info")

        return ParsedFinding(
            title=f"{ctrl_id}: {title}",
            severity=Severity.normalize(severity),
            tool="trivy_operator",
            description=ctrl.get("description", ""),
            asset=service or "unknown",
            tags=["trivy-operator", "compliance"],
            raw_data=ctrl,
        )
