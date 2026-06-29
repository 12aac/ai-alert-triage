"""
pipeline.py
-----------
Orchestrates the full triage flow:

    load alerts
      -> STAGE 1 (Isolation Forest + rules)  routes every alert
      -> STAGE 2 (Claude API)                judges only the 'review' alerts
      -> merge into one final_decision per alert
      -> metrics report (vs ground truth)
      -> ticket-ready JSON for the escalated alerts

Run:  python -m src.pipeline
"""

import json

import pandas as pd

from src.stage1_prefilter import run_stage1, Stage1Config
from src.stage2_classifier import classify_alert
from src.metrics import compute_metrics, format_report
from src.ticketing import write_tickets


def run_pipeline(csv_path: str = "data/sample_alerts.csv") -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    # ---- Stage 1: route everything cheaply ----
    df = run_stage1(df, Stage1Config())

    # ---- Stage 2: only the ambiguous 'review' alerts hit the LLM ----
    final_decisions, rationales, actions, sources = [], [], [], []
    for _, row in df.iterrows():
        if row["stage1_decision"] == "review":
            verdict = classify_alert(row.to_dict())
            final_decisions.append(verdict["verdict"])
            rationales.append(verdict.get("rationale", ""))
            actions.append(verdict.get("recommended_action", ""))
            sources.append(verdict.get("source", ""))
        else:
            # Stage 1 was confident; carry its decision straight through.
            final_decisions.append(row["stage1_decision"])
            rationales.append("Stage 1 rule/score decision.")
            actions.append("Auto-handled by Stage 1.")
            sources.append("stage1")

    df["final_decision"] = final_decisions
    df["rationale"] = rationales
    df["recommended_action"] = actions
    df["source"] = sources

    # ---- Reporting ----
    metrics = compute_metrics(df)
    with open("outputs/metrics.json", "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(format_report(metrics))

    # ---- Tickets for Project 3 ----
    n = write_tickets(df.to_dict("records"))
    print(f"Wrote {n} tickets to outputs/tickets.json")

    df.to_csv("outputs/triaged_alerts.csv", index=False)
    return df


if __name__ == "__main__":
    run_pipeline()
