"""
explain.py
----------
Per-alert explainability: WHICH features made this alert anomalous?

Approach: robust z-scores (median/MAD) per feature. For any alert, the
features with the largest |z| are the ones that deviate most from baseline —
a transparent, analyst-friendly answer to "why did this fire?". This is not
SHAP; it's deliberately simple, fast, and explainable to a non-ML reviewer.
"""

import numpy as np
import pandas as pd

from src.stage1_prefilter import FEATURES


def add_explanations(df: pd.DataFrame, top_k: int = 3) -> pd.DataFrame:
    """Adds a 'top_drivers' column like 'src_bytes(+8.1σ), duration(+3.2σ)'."""
    df = df.copy()
    feats = [c for c in FEATURES if c in df.columns]

    med = df[feats].median()
    mad = (df[feats] - med).abs().median().replace(0, 1e-9)
    z = (df[feats] - med) / (1.4826 * mad)   # 1.4826 ≈ MAD->σ for normal data

    def describe(row_z) -> str:
        top = row_z.abs().sort_values(ascending=False).head(top_k)
        parts = []
        for feat in top.index:
            v = row_z[feat]
            if abs(v) < 1.5:          # not meaningfully unusual
                continue
            sign = "+" if v > 0 else "-"
            parts.append(f"{feat}({sign}{abs(v):.1f}\u03c3)")
        return ", ".join(parts) if parts else "near baseline"

    df["top_drivers"] = [describe(z.iloc[i]) for i in range(len(df))]
    return df
