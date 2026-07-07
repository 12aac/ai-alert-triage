"""Ticket generation tests."""
from src.ticketing import build_tickets


def test_only_ticketable_lanes_get_tickets():
    records = [
        {"alert_id": "A1", "final_decision": "escalate", "anomaly_score": 0.9},
        {"alert_id": "A2", "final_decision": "auto_suppress", "anomaly_score": 0.1},
        {"alert_id": "A3", "final_decision": "needs_review", "anomaly_score": 0.5},
    ]
    tickets = build_tickets(records)
    assert len(tickets) == 2
    assert {t["source_alert_id"] for t in tickets} == {"A1", "A3"}


def test_severity_mapping():
    t = build_tickets([{"alert_id": "X", "final_decision": "escalate",
                        "anomaly_score": 0.8}])[0]
    assert t["severity"] == "High" and t["status"] == "Open"
