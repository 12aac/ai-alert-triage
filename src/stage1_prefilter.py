"""
stage1_prefilter.py
-------------------
STAGE 1 — the cheap, fast pre-filter.

Every alert gets an Isolation Forest anomaly score plus a couple of hard
rules. Based on that, each alert is routed to one of three lanes:

    auto_suppress  -> clearly normal. Treated as a likely false positive,
                      no human and no LLM needed.
    escalate       -> clearly anomalous. Sent straight to a ticket.
    review         -> ambiguous middle band. Handed to STAGE 2 (the LLM)
                      for a judgement call.

The whole point of Stage 1 is to spend the expensive Stage 2 budget ONLY on
the alerts that genuinely need it. That is what "automating false-positive
analysis" means in practice: kill the obvious noise cheaply.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Numeric columns the model learns from. This is a *superset*: run_stage1 uses
# whichever of these are actually present, so it works on synthetic data (first
# five) and on richer real data (e.g. UNSW-NB15 adds TTL/load/state features).
FEATURES = ["duration", "src_bytes", "dst_bytes", "pkt_count", "failed_logins",
            "src_ttl", "dst_ttl", "src_load", "dst_load", "state_ttl_count"]


@dataclass
class Stage1Config:
    contamination: float = 0.05   # expected fraction of anomalies
    suppress_pct: int = 50        # bottom X% of anomaly scores -> auto-suppress
    escalate_pct: int = 95        # top (100-X)% -> escalate straight to ticket
    failed_login_rule: int = 10   # >= this many failed logins always escalates


def run_stage1(df: pd.DataFrame, cfg: Stage1Config = Stage1Config()) -> pd.DataFrame:
    """Adds 'anomaly_score' and 'stage1_decision' columns to a copy of df.

    Robust to real-world data: uses whichever of the expected FEATURES are
    actually present (real SIEM exports rarely have every field), as long as
    at least two numeric features exist.
    """
    df = df.copy()

    feats = [c for c in FEATURES if c in df.columns]
    if len(feats) < 2:
        raise ValueError(
            f"Need at least 2 of these numeric features to score alerts: "
            f"{FEATURES}. Found: {feats}. Check your column mapping."
        )
    has_logins = "failed_logins" in df.columns

    X = StandardScaler().fit_transform(df[feats].astype(float).values)
    model = IsolationForest(
        contamination=cfg.contamination,
        random_state=42,
        n_estimators=200,
    )
    model.fit(X)

    # score_samples: higher = more normal. Flip so higher = more anomalous,
    # then min-max normalize to [0, 1] so thresholds downstream are meaningful.
    raw = -model.score_samples(X)
    span = raw.max() - raw.min()
    df["anomaly_score"] = (raw - raw.min()) / span if span else 0.0

    low = np.percentile(df["anomaly_score"], cfg.suppress_pct)
    high = np.percentile(df["anomaly_score"], cfg.escalate_pct)

    def route(row):
        # Hard rule first: a brute-force burst is never "suppressed"
        # (only when the data actually has a failed_logins field).
        if has_logins and row["failed_logins"] >= cfg.failed_login_rule:
            return "escalate"
        if row["anomaly_score"] <= low:
            return "auto_suppress"
        if row["anomaly_score"] >= high:
            return "escalate"
        return "review"

    df["stage1_decision"] = df.apply(route, axis=1)
    return df


if __name__ == "__main__":
    data = pd.read_csv("data/sample_alerts.csv")
    out = run_stage1(data)
    print(out["stage1_decision"].value_counts())
