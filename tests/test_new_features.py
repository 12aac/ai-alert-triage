"""Tests for report, explainability, and config."""
import pandas as pd

from src.generate_sample_data import make_dataset
from src.pipeline import run_pipeline
from src.report import build_report
from src.explain import add_explanations
from src.config import stage1_config


def test_report_contains_key_sections():
    df = run_pipeline(make_dataset(150, 10), write_files=False)
    text = build_report(df, source_name="test", contamination=0.05)
    for section in ["# Alert Triage Report", "## Outcome",
                    "## Detection quality", "## Top escalated alerts"]:
        assert section in text


def test_report_unlabelled_graceful():
    df = run_pipeline(make_dataset(100, 5).drop(columns=["label"]),
                      write_files=False)
    text = build_report(df, source_name="siem")
    assert "not computable" in text


def test_explanations_added_by_pipeline():
    df = run_pipeline(make_dataset(100, 10), write_files=False)
    assert "top_drivers" in df.columns
    assert df["top_drivers"].str.len().gt(0).all()


def test_extreme_alert_gets_named_driver():
    data = make_dataset(200, 5)
    data.loc[0, "src_bytes"] = 10_000_000
    out = add_explanations(run_pipeline(data, write_files=False))
    # row order preserved by pipeline; find our alert
    row = out[out["src_bytes"] == 10_000_000].iloc[0]
    assert "src_bytes" in row["top_drivers"]


def test_config_loader_defaults_and_yaml():
    cfg = stage1_config({})              # empty -> defaults
    assert cfg.contamination == 0.05
    cfg2 = stage1_config({"stage1": {"contamination": 0.03}})
    assert cfg2.contamination == 0.03
