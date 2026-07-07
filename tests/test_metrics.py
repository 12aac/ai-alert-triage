"""Metrics tests, incl. the unlabelled-data path."""
import pandas as pd

from src.metrics import compute_metrics, format_report


def _df(decisions, labels=None):
    d = {"final_decision": decisions}
    if labels is not None:
        d["label"] = labels
    return pd.DataFrame(d)


def test_perfect_detection():
    df = _df(["escalate", "auto_suppress"], [1, 0])
    m = compute_metrics(df)
    assert m["precision"] == 1.0 and m["recall"] == 1.0


def test_missed_threat_counts_as_fn():
    df = _df(["auto_suppress"], [1])
    m = compute_metrics(df)
    assert m["false_negatives"] == 1 and m["recall"] == 0.0


def test_unlabelled_data_graceful():
    df = _df(["escalate", "auto_suppress", "false_positive"])
    m = compute_metrics(df)
    assert m["has_labels"] is False
    assert m["precision"] is None
    assert m["analyst_workload_reduction"] > 0
    assert "no ground-truth" in format_report(m)


def test_workload_reduction_math():
    df = _df(["auto_suppress", "false_positive", "escalate", "needs_review"],
             [0, 0, 1, 0])
    m = compute_metrics(df)
    assert m["analyst_workload_reduction"] == 0.5
