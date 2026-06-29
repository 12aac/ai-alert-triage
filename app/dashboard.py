"""
dashboard.py
------------
A small Streamlit dashboard over the triage pipeline.

Run:  streamlit run app/dashboard.py
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Make 'src' importable when Streamlit runs this file directly.
sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.stage1_prefilter import Stage1Config  # noqa: E402
from src.pipeline import run_pipeline           # noqa: E402
from src.metrics import compute_metrics         # noqa: E402

st.set_page_config(page_title="AI Alert Triage", layout="wide")
st.title("AI False-Positive Triage Pipeline")
st.caption("Isolation Forest pre-filter + Claude API classification")

with st.sidebar:
    st.header("Run")
    st.write("Uses `data/sample_alerts.csv` by default.")
    run = st.button("Run triage", type="primary")

if run:
    with st.spinner("Triaging alerts..."):
        df = run_pipeline()
        m = compute_metrics(df)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", m["precision"])
    c2.metric("Recall", m["recall"])
    c3.metric("FP suppression", m["fp_suppression_rate"])
    c4.metric("Workload reduction", m["analyst_workload_reduction"])

    st.subheader("Decision breakdown")
    st.bar_chart(df["final_decision"].value_counts())

    st.subheader("Triaged alerts")
    st.dataframe(
        df[["alert_id", "src_ip", "dst_ip", "anomaly_score",
            "stage1_decision", "final_decision", "rationale"]],
        use_container_width=True,
    )
else:
    st.info("Press **Run triage** in the sidebar to process the sample alerts.")
