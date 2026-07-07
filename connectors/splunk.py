"""
connectors/splunk.py
--------------------
Pull alerts from Splunk via a search job and reshape into the pipeline schema.
Secondary to the Elastic connector; provided so the project speaks to both of
the SIEMs you've worked with (ELK + Splunk).

Two common approaches:
  1. The official SDK:  pip install splunk-sdk
  2. The REST API directly (shown below in outline) via requests.

    from connectors.splunk import fetch_alerts
    df = fetch_alerts(host="https://localhost:8089", token="...",
                      spl='search index=security | head 1000')
"""

import os
import pandas as pd

FIELD_MAP = {
    "duration":      "duration",
    "src_bytes":     "bytes_out",
    "dst_bytes":     "bytes_in",
    "pkt_count":     "packets",
    "failed_logins": "failures",
    "label":         "label",
}


def fetch_alerts(
    host: str = None,
    token: str = None,
    spl: str = 'search index=security | head 1000',
    field_map: dict = None,
) -> pd.DataFrame:
    """Run an SPL search and return a DataFrame in the pipeline schema.

    Implemented with the official SDK. Install with:  pip install splunk-sdk
    """
    host = host or os.getenv("SPLUNK_HOST", "https://localhost:8089")
    token = token or os.getenv("SPLUNK_TOKEN")
    field_map = field_map or FIELD_MAP

    try:
        import splunklib.client as client
        import splunklib.results as results
    except ImportError as exc:
        raise ImportError(
            "The 'splunk-sdk' package is required for the Splunk connector. "
            "Install it with:  pip install splunk-sdk"
        ) from exc

    service = client.connect(host=host, token=token)
    job = service.jobs.oneshot(spl, output_mode="json")

    rows = []
    for item in results.JSONResultsReader(job):
        if isinstance(item, dict):
            row = {col: item[f] for col, f in field_map.items() if f in item}
            if row:
                rows.append(row)

    if not rows:
        raise ValueError("Splunk search returned no rows. Check the SPL and field_map.")

    df = pd.DataFrame(rows)
    feature_cols = [c for c in field_map if c != "label" and c in df.columns]
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=feature_cols).reset_index(drop=True)
    df.insert(0, "alert_id", [f"SPL-{i:05d}" for i in range(len(df))])
    df["src_ip"] = df.get("src_ip", "—")
    df["dst_ip"] = df.get("dst_ip", "—")
    return df
