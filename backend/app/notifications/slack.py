import os
import httpx
from typing import Optional

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
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "plain_text", "text": f"Title:\n{title}"[:2000]},
                {"type": "plain_text", "text": f"Asset:\n{asset}"[:2000]},
                {"type": "plain_text", "text": f"Tool:\n{tool}"[:2000]},
                {"type": "plain_text", "text": f"Risk Score:\n{risk_score}"},
            ],
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Finding ID: `{finding_id}`"}],
        },
    ]

    payload = {
        "text": f"{emoji} {severity.upper()}: {title} on {asset}",
        "mrkdwn": False,
        "attachments": [{"color": color, "blocks": blocks}],
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook_url, json=payload)
            return {"ok": response.status_code == 200, "status": response.status_code,
                    "retryable": response.status_code == 429 or response.status_code >= 500,
                    "error": f"Slack returned HTTP {response.status_code}"}
    except httpx.HTTPError:
        return {"ok": False, "error": "Slack connection failed", "retryable": True}


# Alias so existing imports of send_slack_notification still work
send_slack_notification = send_slack_notification_sync
