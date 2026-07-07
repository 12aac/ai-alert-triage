"""
connectors/ticket_push.py
-------------------------
Push escalated alerts into a real ticketing tool via REST — closing the loop
from "AI decided this needs a human" to "a ticket exists in the queue".

Supports:
  * Jira Cloud   — POST /rest/api/3/issue  (email + API token, basic auth)
  * ServiceNow   — POST /api/now/table/incident  (basic auth on a PDI)

Credentials come from env vars (put them in .env, which is gitignored):
  JIRA_URL, JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT_KEY
  SNOW_URL, SNOW_USER, SNOW_PASSWORD

Usage:
    from connectors.ticket_push import push_to_jira, push_to_servicenow
    results = push_to_jira(tickets)          # tickets = build_tickets(...)
"""

import os

import requests

TIMEOUT = 15


def push_to_jira(tickets: list[dict], url: str = None, email: str = None,
                 token: str = None, project_key: str = None) -> list[dict]:
    """Create one Jira issue per ticket. Returns [{alert_id, key|error}]."""
    url = (url or os.getenv("JIRA_URL", "")).rstrip("/")
    email = email or os.getenv("JIRA_EMAIL")
    token = token or os.getenv("JIRA_TOKEN")
    project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "SEC")
    if not (url and email and token):
        raise ValueError("Set JIRA_URL, JIRA_EMAIL and JIRA_TOKEN (e.g. in .env).")

    results = []
    for t in tickets:
        desc = (f"Anomaly score: {t['anomaly_score']}\n"
                f"Source IPs: {t.get('src_ip')} -> {t.get('dst_ip')}\n"
                f"Rationale: {t.get('rationale','')}\n"
                f"Recommended action: {t.get('recommended_action','')}\n"
                f"Decided by: {t.get('decided_by','')}")
        payload = {"fields": {
            "project": {"key": project_key},
            "summary": t["summary"],
            "issuetype": {"name": "Task"},
            "description": {   # Atlassian Document Format
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": desc}]}],
            },
        }}
        try:
            r = requests.post(f"{url}/rest/api/3/issue", json=payload,
                              auth=(email, token), timeout=TIMEOUT)
            r.raise_for_status()
            results.append({"alert_id": t["source_alert_id"],
                            "key": r.json().get("key")})
        except Exception as exc:
            results.append({"alert_id": t["source_alert_id"],
                            "error": str(exc)})
    return results


def push_to_servicenow(tickets: list[dict], url: str = None, user: str = None,
                       password: str = None) -> list[dict]:
    """Create one ServiceNow incident per ticket on a PDI."""
    url = (url or os.getenv("SNOW_URL", "")).rstrip("/")
    user = user or os.getenv("SNOW_USER")
    password = password or os.getenv("SNOW_PASSWORD")
    if not (url and user and password):
        raise ValueError("Set SNOW_URL, SNOW_USER and SNOW_PASSWORD (e.g. in .env).")

    sev_to_urgency = {"High": "1", "Medium": "2", "Low": "3"}
    results = []
    for t in tickets:
        payload = {
            "short_description": t["summary"],
            "urgency": sev_to_urgency.get(t["severity"], "2"),
            "description": (f"Anomaly score: {t['anomaly_score']}\n"
                            f"Rationale: {t.get('rationale','')}\n"
                            f"Recommended action: {t.get('recommended_action','')}"),
            "category": "security",
        }
        try:
            r = requests.post(f"{url}/api/now/table/incident", json=payload,
                              auth=(user, password),
                              headers={"Accept": "application/json"},
                              timeout=TIMEOUT)
            r.raise_for_status()
            results.append({"alert_id": t["source_alert_id"],
                            "number": r.json()["result"].get("number")})
        except Exception as exc:
            results.append({"alert_id": t["source_alert_id"],
                            "error": str(exc)})
    return results
