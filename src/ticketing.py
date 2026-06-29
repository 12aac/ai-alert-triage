"""
ticketing.py
------------
Converts alerts the pipeline decided a human should see into ticket-ready
JSON. This is the seam that connects Project 1 to Project 3 (ServiceNow /
Jira): in Project 3 you POST these objects to a ticketing REST API.

A ticket is created for any alert whose final_decision is 'escalate',
'true_positive', or 'needs_review'. Auto-suppressed / false-positive alerts
produce no ticket — that is the noise reduction, made visible.
"""

import json

TICKETABLE = {"escalate", "true_positive", "needs_review"}

SEVERITY = {
    "escalate": "High",
    "true_positive": "High",
    "needs_review": "Medium",
}


def alert_to_ticket(row: dict) -> dict:
    decision = row["final_decision"]
    return {
        "summary": f"Security alert {row['alert_id']} — {decision}",
        "severity": SEVERITY.get(decision, "Medium"),
        "source_alert_id": row["alert_id"],
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "anomaly_score": round(float(row.get("anomaly_score", 0)), 3),
        "rationale": row.get("rationale", ""),
        "recommended_action": row.get("recommended_action", ""),
        "decided_by": row.get("source", "stage1"),
        "status": "Open",
    }


def build_tickets(records: list[dict]) -> list[dict]:
    return [alert_to_ticket(r) for r in records
            if r.get("final_decision") in TICKETABLE]


def write_tickets(records: list[dict], path: str = "outputs/tickets.json") -> int:
    tickets = build_tickets(records)
    with open(path, "w") as fh:
        json.dump(tickets, fh, indent=2)
    return len(tickets)
