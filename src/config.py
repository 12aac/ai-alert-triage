"""
config.py
---------
Loads config.yaml so thresholds/models/paths live in one editable file
instead of scattered constants. Falls back to defaults if the file is absent.
"""

from pathlib import Path

from src.stage1_prefilter import Stage1Config

_ROOT = Path(__file__).resolve().parents[1]


def load_config(path: str | Path = None) -> dict:
    path = Path(path) if path else _ROOT / "config.yaml"
    if not path.exists():
        return {}
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        return {}   # pyyaml not installed — defaults apply


def stage1_config(cfg: dict = None) -> Stage1Config:
    cfg = cfg if cfg is not None else load_config()
    s1 = cfg.get("stage1", {})
    return Stage1Config(
        contamination=s1.get("contamination", 0.05),
        suppress_pct=s1.get("suppress_pct", 50),
        escalate_pct=s1.get("escalate_pct", 95),
        failed_login_rule=s1.get("failed_login_rule", 10),
    )
