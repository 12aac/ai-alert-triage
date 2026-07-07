"""
viz.py
------
Plotly figures that tell the triage story (not decoration). Each function takes
the triaged DataFrame (or metrics dict) and returns a themed Figure.

No Streamlit dependency here on purpose — these are pure and testable.
"""

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from src.theme import PALETTE, DECISION_COLORS, apply_dark
from src.stage1_prefilter import Stage1Config


def lane_donut(df: pd.DataFrame) -> go.Figure:
    """Where did every alert end up? Donut with total in the centre."""
    counts = df["final_decision"].value_counts()
    colors = [DECISION_COLORS.get(k, PALETTE["grey"]) for k in counts.index]
    fig = go.Figure(go.Pie(
        labels=counts.index, values=counts.values, hole=0.62,
        marker=dict(colors=colors, line=dict(color=PALETTE["bg"], width=2)),
        textinfo="label+percent", textfont=dict(size=12),
        hovertemplate="%{label}: %{value} alerts<extra></extra>",
    ))
    fig.add_annotation(text=f"<b>{len(df)}</b><br>alerts", showarrow=False,
                       font=dict(size=20, color=PALETTE["ink"]))
    fig.update_layout(title="Decision breakdown", showlegend=False, height=360)
    return apply_dark(fig)


def score_histogram(df: pd.DataFrame, cfg: Stage1Config = Stage1Config()) -> go.Figure:
    """Anomaly-score distribution with the routing threshold bands drawn on."""
    low = np.percentile(df["anomaly_score"], cfg.suppress_pct)
    high = np.percentile(df["anomaly_score"], cfg.escalate_pct)

    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=df["anomaly_score"], nbinsx=50,
        marker=dict(color=PALETTE["cyan"], line=dict(width=0)),
        opacity=0.85, name="alerts",
        hovertemplate="score %{x:.2f}: %{y}<extra></extra>",
    ))
    smin, smax = df["anomaly_score"].min(), df["anomaly_score"].max()
    # threshold bands (no inline annotations — labels added above the plot)
    fig.add_vrect(x0=smin, x1=low, fillcolor=PALETTE["green"],
                  opacity=0.10, line_width=0)
    fig.add_vrect(x0=low, x1=high, fillcolor=PALETTE["amber"],
                  opacity=0.08, line_width=0)
    fig.add_vrect(x0=high, x1=smax, fillcolor=PALETTE["red"],
                  opacity=0.10, line_width=0)

    # band labels as pills ABOVE the plot area, so bars never overlap them
    band_centers = [
        ((smin + low) / 2, "suppress", PALETTE["green"]),
        ((low + high) / 2, "review",   PALETTE["amber"]),
        ((high + smax) / 2, "escalate", PALETTE["red"]),
    ]
    for xc, label, color in band_centers:
        fig.add_annotation(
            x=xc, y=1.06, xref="x", yref="paper", text=label,
            showarrow=False, font=dict(size=12, color=PALETTE["bg"]),
            bgcolor=color, borderpad=4, opacity=0.95,
        )
    fig.update_layout(title="Anomaly scores & routing thresholds",
                      bargap=0.02, height=380,
                      margin=dict(t=70),
                      xaxis_title="anomaly score (0–1)", yaxis_title="alerts")
    return apply_dark(fig)


def confusion_heatmap(df: pd.DataFrame) -> go.Figure:
    """2×2 confusion matrix — only meaningful when ground-truth labels exist."""
    from src.metrics import FLAGGED_STATES
    y_true = df["label"].astype(int)
    flagged = df["final_decision"].isin(FLAGGED_STATES).astype(int)
    tp = int(((flagged == 1) & (y_true == 1)).sum())
    fp = int(((flagged == 1) & (y_true == 0)).sum())
    fn = int(((flagged == 0) & (y_true == 1)).sum())
    tn = int(((flagged == 0) & (y_true == 0)).sum())

    z = [[tn, fp], [fn, tp]]
    text = [[f"TN<br>{tn}", f"FP<br>{fp}"], [f"FN<br>{fn}", f"TP<br>{tp}"]]
    fig = go.Figure(go.Heatmap(
        z=z, text=text, texttemplate="%{text}",
        x=["pred: cleared", "pred: flagged"],
        y=["actual: benign", "actual: threat"],
        colorscale=[[0, PALETTE["panel"]], [1, PALETTE["cyan"]]],
        showscale=False, hoverinfo="skip",
        textfont=dict(size=14, color=PALETTE["ink"]),
    ))
    fig.update_layout(title="Confusion matrix", height=360)
    return apply_dark(fig)


def impact_bar(metrics: dict) -> go.Figure:
    """How much human work was removed: auto-handled vs needs-a-human."""
    total = metrics["alerts_total"]
    auto = round(metrics["analyst_workload_reduction"] * total)
    human = total - auto
    fig = go.Figure(go.Bar(
        x=[auto, human], y=["", ""], orientation="h",
        marker=dict(color=[PALETTE["green"], PALETTE["amber"]]),
        text=[f"auto-handled: {auto}", f"needs analyst: {human}"],
        textposition="inside", insidetextanchor="middle",
        hovertemplate="%{text}<extra></extra>",
    ))
    fig.update_layout(
        title="Analyst workload removed", barmode="stack", height=180,
        showlegend=False, xaxis=dict(visible=False), yaxis=dict(visible=False))
    return apply_dark(fig)
