"""
dashboard.py
------------
Themed Streamlit dashboard for the AI Alert Triage pipeline.

Features:
  - Source switcher: synthetic sample, CSV upload, or live Elasticsearch.
  - Metric cards + four story-telling Plotly charts on the project palette.
  - Gracefully handles unlabelled SIEM data (hides detection-quality charts).

Run:  streamlit run app/dashboard.py
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.theme import PALETTE                                   # noqa: E402
from src.pipeline import run_pipeline                           # noqa: E402
from src.metrics import compute_metrics                         # noqa: E402
from src.generate_sample_data import make_dataset               # noqa: E402
from src.viz import (lane_donut, score_histogram,               # noqa: E402
                     confusion_heatmap, impact_bar)

st.set_page_config(page_title="AI Alert Triage", layout="wide",
                   page_icon="\U0001F6E1")

# ---- global theme (CSS) ----
st.markdown(f"""
<style>
  .stApp {{ background:{PALETTE['bg']}; color:{PALETTE['ink']}; }}
  section[data-testid="stSidebar"] {{ background:{PALETTE['panel']}; }}
  h1,h2,h3,h4 {{ color:{PALETTE['ink']}; }}
  .eyebrow {{ color:{PALETTE['cyan']}; font-family:monospace;
              letter-spacing:3px; font-size:12px; }}
  .sub {{ color:{PALETTE['mute']}; font-family:monospace; }}
  .card {{ background:{PALETTE['panel']}; border:1px solid {PALETTE['grid']};
           border-radius:14px; padding:16px 18px; }}
  .card .val {{ font-size:30px; font-weight:700; }}
  .card .lab {{ color:{PALETTE['mute']}; font-family:monospace;
                font-size:12px; letter-spacing:1px; }}
  .stTabs [data-baseweb="tab-list"] {{ gap:4px; }}
  .stTabs [data-baseweb="tab"] {{ background:{PALETTE['panel']};
       border-radius:10px 10px 0 0; color:{PALETTE['mute']}; }}
  .stTabs [aria-selected="true"] {{ color:{PALETTE['cyan']}; }}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="eyebrow">SOC &middot; DETECTION ENGINEERING</div>',
            unsafe_allow_html=True)
st.title("AI Alert Triage")
st.markdown('<div class="sub">Isolation Forest pre-filter '
            '&middot; Claude API classification</div>', unsafe_allow_html=True)
st.write("")

# ---- sidebar: source switcher ----
with st.sidebar:
    st.header("Data source")
    source_kind = st.radio(
        "Where do the alerts come from?",
        ["Synthetic sample", "Upload CSV", "Elasticsearch"],
        captions=["Built-in labelled demo data",
                  "Your own labelled CSV",
                  "Live query against an ES index"],
    )

    uploaded = None
    es_cfg = {}
    if source_kind == "Upload CSV":
        uploaded = st.file_uploader("Alerts CSV", type=["csv"])
    elif source_kind == "Elasticsearch":
        es_cfg["host"] = st.text_input("Host", "https://localhost:9200")
        es_cfg["index"] = st.text_input("Index", "unsw-nb15-*")
        es_cfg["api_key"] = st.text_input("API key", type="password")
        es_cfg["size"] = st.number_input("Max docs", 100, 10000, 1000, step=100)
        es_cfg["verify"] = st.checkbox(
            "Verify TLS certificate", value=True,
            help="Uncheck only for lab clusters with self-signed certs.")

    run = st.button("Run triage", type="primary", use_container_width=True)
    st.divider()
    st.caption("Stage 1 tuning")
    contamination = st.slider(
        "Expected attack rate (contamination)", 0.01, 0.15, 0.05, 0.01,
        help="Set near your data's real attack ratio. UNSW-NB15 ≈ 0.03; "
             "synthetic sample ≈ 0.05.")
    st.caption("Tip: set ANTHROPIC_API_KEY in .env to enable the real "
               "Claude classification (otherwise an offline fallback is used).")


def _read_uploaded(file) -> pd.DataFrame:
    """Read an uploaded CSV. If it's already in the pipeline schema, use it as
    is; if it looks like a UNSW-NB15 file (raw headerless or preprocessed),
    auto-convert it so the user doesn't have to run the converter by hand."""
    import io
    data = file.getvalue()
    df = pd.read_csv(io.BytesIO(data), low_memory=False)

    expected = {"duration", "src_bytes", "dst_bytes", "pkt_count"}
    if expected & set(df.columns):
        return df  # already in (or close to) the pipeline schema

    try:
        from tools.convert_unsw import to_pipeline_schema, RAW_COLS
        if df.shape[1] == len(RAW_COLS):          # raw, headerless UNSW file
            df = pd.read_csv(io.BytesIO(data), header=None,
                             names=RAW_COLS, low_memory=False)
        converted = to_pipeline_schema(df)
        if {"duration", "src_bytes", "dst_bytes"} <= set(converted.columns):
            st.info("Detected a UNSW-NB15 file — auto-converted to the "
                    "pipeline schema. (Set the attack-rate slider to ~0.03.)")
            return converted
    except Exception:
        pass

    st.error("This CSV doesn't have the expected columns "
             "(duration, src_bytes, dst_bytes, pkt_count). Convert it first "
             "with tools/convert_unsw.py, or upload a schema-matching file.")
    st.stop()


def load_source() -> pd.DataFrame:
    if source_kind == "Synthetic sample":
        return make_dataset()
    if source_kind == "Upload CSV":
        if uploaded is None:
            st.warning("Upload a CSV first.")
            st.stop()
        return _read_uploaded(uploaded)
    # Elasticsearch
    from connectors.elastic import fetch_alerts
    try:
        return fetch_alerts(host=es_cfg["host"], index=es_cfg["index"],
                            api_key=es_cfg["api_key"] or None,
                            size=int(es_cfg["size"]),
                            verify_certs=es_cfg.get("verify", True))
    except Exception as exc:
        st.error(f"Elasticsearch fetch failed: {exc}")
        st.stop()


def card(col, value, label, color):
    col.markdown(
        f'<div class="card"><div class="val" style="color:{color}">{value}</div>'
        f'<div class="lab">{label}</div></div>', unsafe_allow_html=True)


if not run:
    st.info("Pick a data source in the sidebar and press **Run triage**.")
    st.stop()

with st.spinner("Triaging alerts..."):
    from src.stage1_prefilter import Stage1Config
    raw = load_source()
    df = run_pipeline(raw, write_files=False, cfg=Stage1Config(contamination=contamination))
    m = compute_metrics(df)

# ---- metric cards ----
c1, c2, c3, c4 = st.columns(4)
card(c1, m["alerts_total"], "ALERTS PROCESSED", PALETTE["cyan"])
card(c2, f'{m["analyst_workload_reduction"]:.0%}',
     "ANALYST WORKLOAD REMOVED", PALETTE["green"])
if m["has_labels"]:
    card(c3, m["recall"], "RECALL (THREATS CAUGHT)", PALETTE["amber"])
    card(c4, m["precision"], "PRECISION", PALETTE["red"])
else:
    card(c3, m["flagged_for_human"], "FLAGGED FOR ANALYST", PALETTE["amber"])
    card(c4, "n/a", "PRECISION (needs labels)", PALETTE["mute"])
st.write("")

# ---- tabbed visualizations ----
tabs = st.tabs(["Overview", "Anomaly scores", "Detection quality", "Impact",
                "Alerts table"])

with tabs[0]:
    st.plotly_chart(lane_donut(df), use_container_width=True)

with tabs[1]:
    st.plotly_chart(score_histogram(df), use_container_width=True)
    st.caption("Bands show how Stage 1 routes alerts by anomaly score. The "
               "amber 'review' band is what gets sent to the Claude API.")

with tabs[2]:
    if m["has_labels"]:
        col_a, col_b = st.columns([1, 1])
        col_a.plotly_chart(confusion_heatmap(df), use_container_width=True)
        col_b.metric("F1 score", m["f1"])
        col_b.metric("False-positive rate", m["false_positive_rate"])
        col_b.metric("FP auto-suppression rate", m["fp_suppression_rate"])
    else:
        st.info("This source has no ground-truth `label` column, so detection "
                "quality (precision/recall/confusion matrix) can't be computed. "
                "Operational metrics are still available in the other tabs.")

with tabs[3]:
    st.plotly_chart(impact_bar(m), use_container_width=True)
    st.caption(f"{m['analyst_workload_reduction']:.0%} of alerts were resolved "
               "without analyst time.")

with tabs[4]:
    cols = ["alert_id", "src_ip", "dst_ip", "anomaly_score",
            "stage1_decision", "final_decision", "top_drivers", "rationale"]
    st.dataframe(df[[c for c in cols if c in df.columns]],
                 use_container_width=True, height=420)
    st.caption("`top_drivers` shows which features pushed each alert away "
               "from baseline (robust z-scores) — the 'why did this fire?' "
               "answer an analyst asks first.")
