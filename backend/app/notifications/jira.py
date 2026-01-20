import os
import httpx
from typing import Optional
import base64

SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


def create_jira_issue_sync(
    title: str,
    severity: str,
    asset: str,
    risk_score: int,
    finding_id: str,
    tool: str,
    description: str = "",
) -> Optional[dict]:
    jira_base = os.environ.get("JIRA_BASE_URL")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_project = os.environ.get("JIRA_PROJECT_KEY")

    if not all([jira_base, jira_email, jira_token, jira_project]):
        return None

    priority = SEVERITY_TO_PRIORITY.get(severity.lower(), "Medium")
    
    issue_description = f"""
h2. Security Finding Details

||Field||Value||
|Finding ID|{finding_id}|
|Tool|{tool}|
|Asset|{asset}|
|Severity|{severity.upper()}|
|Risk Score|{risk_score}|

h3. Description
{description or 'No additional description provided.'}

----
_This issue was automatically created by the SecOps Dashboard._
"""

    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": f"[{severity.upper()}] {title} - {asset}",
            "description": issue_description,
            "issuetype": {"name": "Bug"},
            "labels": ["security", "secops-dashboard", severity.lower()],
        }
    }

    auth_str = f"{jira_email}:{jira_token}"
    auth_bytes = base64.b64encode(auth_str.encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_bytes}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                f"{jira_base}/rest/api/3/issue",
                headers=headers,
                json=payload,
            )
            
            if response.status_code in (200, 201):
                data = response.json()
                return {
                    "ok": True,
                    "issue_key": data.get("key"),
                    "issue_id": data.get("id"),
                    "url": f"{jira_base}/browse/{data.get('key')}",
                }
            else:
                return {
                    "ok": False,
                    "status": response.status_code,
                    "error": response.text,
                }
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def create_jira_issue(
    title: str,
    severity: str,
    asset: str,
    risk_score: int,
    finding_id: str,
    tool: str,
    description: str = "",
) -> Optional[dict]:
    jira_base = os.environ.get("JIRA_BASE_URL")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_project = os.environ.get("JIRA_PROJECT_KEY")

    if not all([jira_base, jira_email, jira_token, jira_project]):
        return None

    priority = SEVERITY_TO_PRIORITY.get(severity.lower(), "Medium")
    
    issue_description = f"""
h2. Security Finding Details

||Field||Value||
|Finding ID|{finding_id}|
|Tool|{tool}|
|Asset|{asset}|
|Severity|{severity.upper()}|
|Risk Score|{risk_score}|

h3. Description
{description or 'No additional description provided.'}

----
_This issue was automatically created by the SecOps Dashboard._
"""

    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": f"[{severity.upper()}] {title} - {asset}",
            "description": issue_description,
            "issuetype": {"name": "Bug"},
            "labels": ["security", "secops-dashboard", severity.lower()],
        }
    }

    auth_str = f"{jira_email}:{jira_token}"
    auth_bytes = base64.b64encode(auth_str.encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_bytes}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{jira_base}/rest/api/3/issue",
                headers=headers,
                json=payload,
            )
            
            if response.status_code in (200, 201):
                data = response.json()
                return {
                    "ok": True,
                    "issue_key": data.get("key"),
                    "issue_id": data.get("id"),
                    "url": f"{jira_base}/browse/{data.get('key')}",
                }
            else:
                return {
                    "ok": False,
                    "status": response.status_code,
                    "error": response.text,
                }
    except Exception as e:
        return {"ok": False, "error": str(e)}
