"""
tune_thresholds.py
------------------
Precision/recall tradeoff analysis: sweeps the Stage 1 escalate threshold and
plots how precision and recall move against each other. Answers "why is
precision 0.28?" with evidence instead of hand-waving — and shows where you'd
set the threshold for a different precision/recall preference.

Usage:
  python tools/tune_thresholds.py data/unsw_ready.csv --contamination 0.03
Writes outputs/tuning_curve.html (interactive) and prints the sweep table.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import plotly.graph_objects as go

from src.stage1_prefilter import run_stage1, Stage1Config
from src.metrics import compute_metrics
from src.theme import PALETTE, apply_dark


def sweep(df: pd.DataFrame, contamination: float,
          suppress_range=range(30, 92, 6)) -> pd.DataFrame:
    """Sweep the SUPPRESS threshold — the cut that decides flagged vs cleared,
    and therefore the one that trades precision against recall. (The escalate
    threshold only moves alerts between two flagged lanes.)"""
    rows = []
    for sup in suppress_range:
        out = run_stage1(df, Stage1Config(contamination=contamination,
                                          suppress_pct=sup, escalate_pct=95))
        out["final_decision"] = out["stage1_decision"].map(
            {"auto_suppress": "auto_suppress", "review": "needs_review",
             "escalate": "escalate"})
        m = compute_metrics(out)
        rows.append({"suppress_pct": sup, "precision": m["precision"],
                     "recall": m["recall"], "f1": m["f1"],
                     "workload_reduction": m["analyst_workload_reduction"]})
    return pd.DataFrame(rows)


def plot(sweep_df: pd.DataFrame, path: str = "outputs/tuning_curve.html"):
    fig = go.Figure()
    for col, color in [("precision", PALETTE["red"]),
                       ("recall", PALETTE["amber"]),
                       ("f1", PALETTE["cyan"]),
                       ("workload_reduction", PALETTE["green"])]:
        fig.add_trace(go.Scatter(x=sweep_df["suppress_pct"], y=sweep_df[col],
                                 name=col, line=dict(color=color, width=2)))
    fig.update_layout(title="Stage 1 threshold sweep: precision/recall tradeoff",
                      xaxis_title="suppress threshold (percentile)",
                      yaxis_title="metric value", height=420)
    apply_dark(fig).write_html(path)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--contamination", type=float, default=0.05)
    args = ap.parse_args()

    data = pd.read_csv(args.csv)
    if "label" not in data.columns:
        raise SystemExit("Tuning needs labelled data (a 'label' column).")

    result = sweep(data, args.contamination)
    print(result.to_string(index=False))
    import os
    os.makedirs("outputs", exist_ok=True)
    print("Curve written to", plot(result))
