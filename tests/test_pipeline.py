"""End-to-end pipeline tests (offline heuristic path)."""
import pandas as pd

from src.generate_sample_data import make_dataset
from src.pipeline import run_pipeline
from src.stage1_prefilter import Stage1Config


def test_end_to_end_labelled(tmp_path):
    df = run_pipeline(make_dataset(200, 10), write_files=False)
    assert {"final_decision", "rationale", "recommended_action"} <= set(df.columns)
    assert len(df) == 210


def test_accepts_csv_path(tmp_path):
    p = tmp_path / "alerts.csv"
    make_dataset(100, 5).to_csv(p, index=False)
    df = run_pipeline(str(p), write_files=False)
    assert len(df) == 105


def test_custom_config_changes_routing():
    data = make_dataset(300, 15)
    strict = run_pipeline(data, write_files=False,
                          cfg=Stage1Config(escalate_pct=80))
    loose = run_pipeline(data, write_files=False,
                         cfg=Stage1Config(escalate_pct=99))
    assert (strict["stage1_decision"] == "escalate").sum() > \
           (loose["stage1_decision"] == "escalate").sum()
