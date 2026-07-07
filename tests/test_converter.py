"""UNSW-NB15 converter tests."""
import pandas as pd

from tools.convert_unsw import to_pipeline_schema, RAW_COLS


def _fake_raw(n=20):
    row = {c: 0 for c in RAW_COLS}
    df = pd.DataFrame([row] * n)
    df["dur"] = 0.5
    df["sbytes"] = 100
    df["dbytes"] = 200
    df["Spkts"] = 2
    df["Dpkts"] = 3
    df["sttl"] = 31
    df["label"] = [1, 0] * (n // 2)
    return df


def test_maps_to_pipeline_schema():
    out = to_pipeline_schema(_fake_raw())
    assert {"duration", "src_bytes", "dst_bytes", "pkt_count", "label"} <= set(out.columns)
    assert (out["pkt_count"] == 5).all()


def test_richer_features_included():
    out = to_pipeline_schema(_fake_raw())
    assert "src_ttl" in out.columns


def test_alert_ids_unique():
    out = to_pipeline_schema(_fake_raw())
    assert out["alert_id"].is_unique
