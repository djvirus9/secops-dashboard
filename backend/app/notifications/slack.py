import os
import httpx
from typing import Optional

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":large_blue_circle:",
    "info": ":information_source:",
}

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


def send_slack_notification_sync(
    title: str,
    severity: str,
    asset: str,
    risk_score: int,
    finding_id: str,
    tool: str,
    is_new: bool = True,
    occurrences: int = 1,
) -> Optional[dict]:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return None

    emoji = SEVERITY_EMOJI.get(severity.lower(), ":question:")
    color = SEVERITY_COLOR.get(severity.lower(), "#6b7280")
    
    action_text = "New finding detected" if is_new else f"Seen again (#{occurrences})"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {action_text}: {severity.upper()}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                {"type": "mrkdwn", "text": f"*Asset:*\n{asset}"},
                {"type": "mrkdwn", "text": f"*Tool:*\n{tool}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}"},
            ]
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Finding ID: `{finding_id}`"}
            ]
        }
    ]

    payload = {
        "text": f"{emoji} {severity.upper()}: {title} on {asset}",
        "attachments": [
            {
                "color": color,
                "blocks": blocks
            }
        ]
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook_url, json=payload)
            return {"ok": response.status_code == 200, "status": response.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def send_slack_notification(
    title: str,
    severity: str,
    asset: str,
    risk_score: int,
    finding_id: str,
    tool: str,
    is_new: bool = True,
    occurrences: int = 1,
) -> Optional[dict]:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return None

    emoji = SEVERITY_EMOJI.get(severity.lower(), ":question:")
    color = SEVERITY_COLOR.get(severity.lower(), "#6b7280")
    
    action_text = "New finding detected" if is_new else f"Seen again (#{occurrences})"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {action_text}: {severity.upper()}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                {"type": "mrkdwn", "text": f"*Asset:*\n{asset}"},
                {"type": "mrkdwn", "text": f"*Tool:*\n{tool}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}"},
            ]
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Finding ID: `{finding_id}`"}
            ]
        }
    ]

    payload = {
        "text": f"{emoji} {severity.upper()}: {title} on {asset}",
        "attachments": [
            {
                "color": color,
                "blocks": blocks
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload)
            return {"ok": response.status_code == 200, "status": response.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}
