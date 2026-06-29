"""
metrics.py
----------
Turns the pipeline's final decisions into the numbers a hiring manager (and a
real SOC lead) actually cares about:

    precision / recall / F1   — detection quality vs ground truth
    false_positive_rate       — of all benign alerts, how many we wrongly flagged
    fp_suppression_rate       — of all benign alerts, how many we auto-killed
                                WITHOUT sending a human, i.e. noise removed
    analyst_workload_reduction— fraction of alerts handled without a human

We treat a final decision as "flagged" (predicted threat) when the pipeline
escalates or sends to review; "cleared" when it auto-suppresses or the LLM
calls it a false positive.
"""

import pandas as pd


# Map every possible final state to a binary "did we flag this for a human?"
FLAGGED_STATES = {"escalate", "needs_review", "true_positive"}
CLEARED_STATES = {"auto_suppress", "false_positive"}


def compute_metrics(df: pd.DataFrame) -> dict:
    """df must have 'label' (ground truth) and 'final_decision'."""
    y_true = df["label"].astype(int)
    flagged = df["final_decision"].isin(FLAGGED_STATES).astype(int)

    tp = int(((flagged == 1) & (y_true == 1)).sum())
    fp = int(((flagged == 1) & (y_true == 0)).sum())
    fn = int(((flagged == 0) & (y_true == 1)).sum())
    tn = int(((flagged == 0) & (y_true == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    benign_total = int((y_true == 0).sum())
    false_positive_rate = fp / benign_total if benign_total else 0.0

    auto_suppressed_benign = int(
        ((df["final_decision"] == "auto_suppress") & (y_true == 0)).sum())
    fp_suppression_rate = (auto_suppressed_benign / benign_total
                           if benign_total else 0.0)

    handled_without_human = df["final_decision"].isin(
        {"auto_suppress", "false_positive"}).sum()
    workload_reduction = handled_without_human / len(df) if len(df) else 0.0

    return {
        "alerts_total": len(df),
        "true_positives": tp, "false_positives": fp,
        "false_negatives": fn, "true_negatives": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "fp_suppression_rate": round(fp_suppression_rate, 3),
        "analyst_workload_reduction": round(workload_reduction, 3),
    }


def format_report(m: dict) -> str:
    return (
        "=== Alert Triage Metrics ===\n"
        f"Alerts processed:            {m['alerts_total']}\n"
        f"Precision:                   {m['precision']}\n"
        f"Recall:                      {m['recall']}\n"
        f"F1:                          {m['f1']}\n"
        f"False-positive rate:         {m['false_positive_rate']}\n"
        f"FP auto-suppression rate:    {m['fp_suppression_rate']}\n"
        f"Analyst workload reduction:  {m['analyst_workload_reduction']}\n"
        f"TP/FP/FN/TN: {m['true_positives']}/{m['false_positives']}"
        f"/{m['false_negatives']}/{m['true_negatives']}\n"
    )
