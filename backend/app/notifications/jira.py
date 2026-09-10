"""Jira Cloud v3 delivery using Atlassian Document Format."""
import os
from typing import Optional

import httpx


def create_jira_issue_sync(
    title: str, severity: str, asset: str, risk_score: int, finding_id: str,
    tool: str, description: str = "", recommendation: str = "", project: str = "",
    component: str = "", component_version: str = "",
) -> Optional[dict]:
    jira_base = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_project = os.environ.get("JIRA_PROJECT_KEY")
    if not all((jira_base, jira_email, jira_token, jira_project)):
        return None
    paragraphs = [
        f"Finding ID: {finding_id}", f"Project: {project or 'Unscoped'}",
        f"Tool: {tool}; Asset: {asset}", f"Severity: {severity}; Risk score: {risk_score}",
        f"Component: {component} {component_version}" if component else "",
        description or "No additional description provided.",
        f"Remediation: {recommendation}" if recommendation else "",
    ]
    fields = {
        "project": {"key": jira_project},
        "summary": f"[{severity.upper()}] {title} - {asset}"[:255],
        "description": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text[:20_000]}]}
            for text in paragraphs if text
        ]},
        "issuetype": {"name": os.environ.get("JIRA_ISSUE_TYPE", "Bug")},
        "labels": ["security", "secops-dashboard", severity.lower()],
    }
    priority = os.environ.get(f"JIRA_PRIORITY_{severity.upper()}")
    if priority:
        fields["priority"] = {"name": priority}
    try:
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            response = client.post(f"{jira_base}/rest/api/3/issue", auth=(jira_email, jira_token),
                                   headers={"Accept": "application/json"}, json={"fields": fields})
            if response.status_code in (200, 201):
                data = response.json()
                key = data.get("key")
                if not isinstance(key, str) or not key:
                    return {"ok": False, "unknown_outcome": True}
                return {"ok": True, "issue_key": key, "issue_id": data.get("id"),
                        "url": f"{jira_base}/browse/{key}"}
            return {"ok": False, "status": response.status_code,
                    "error": f"Jira returned HTTP {response.status_code}",
                    "retryable": response.status_code == 429,
                    "unknown_outcome": response.status_code >= 500}
    except (httpx.HTTPError, ValueError):
        return {"ok": False, "unknown_outcome": True}


create_jira_issue = create_jira_issue_sync
