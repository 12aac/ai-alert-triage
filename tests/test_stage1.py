"""Stage 1 pre-filter tests."""
import pandas as pd
import pytest

from src.generate_sample_data import make_dataset
from src.stage1_prefilter import run_stage1, Stage1Config


def test_adds_expected_columns():
    out = run_stage1(make_dataset(100, 10))
    assert {"anomaly_score", "stage1_decision"} <= set(out.columns)


def test_scores_normalized_0_1():
    out = run_stage1(make_dataset(200, 10))
    assert out["anomaly_score"].between(0, 1).all()


def test_decisions_are_valid_lanes():
    out = run_stage1(make_dataset(200, 10))
    assert set(out["stage1_decision"]) <= {"auto_suppress", "review", "escalate"}


def test_failed_login_rule_forces_escalate():
    df = make_dataset(50, 5)
    df.loc[0, "failed_logins"] = 99
    out = run_stage1(df)
    assert out.loc[0, "stage1_decision"] == "escalate"


def test_adaptive_features_missing_failed_logins():
    """Real SIEM data may lack failed_logins — must not crash."""
    df = make_dataset(100, 10).drop(columns=["failed_logins"])
    out = run_stage1(df)
    assert "anomaly_score" in out.columns


def test_too_few_features_raises():
    df = pd.DataFrame({"duration": [1.0, 2.0], "unrelated": [1, 2]})
    with pytest.raises(ValueError):
        run_stage1(df)
