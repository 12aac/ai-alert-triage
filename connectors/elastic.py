"""
connectors/elastic.py
---------------------
Pull alerts straight from an Elasticsearch index and reshape them into the
columns the triage pipeline expects:

    duration, src_bytes, dst_bytes, pkt_count, failed_logins   (features)
    label                                                       (optional truth)

This turns the project from "reads a CSV" into "triages live SIEM data" — the
actual SOC workflow.

CONFIG — everything is overridable so you can point it at YOUR cluster without
touching code. Defaults assume a UNSW-NB15-style index (the kind produced in
the SRT411 Logstash labs); change FIELD_MAP if your field names differ.

    from connectors.elastic import fetch_alerts
    df = fetch_alerts(host="https://localhost:9200", index="unsw-nb15-*",
                      api_key="...", size=2000)

Requires the official client:  pip install elasticsearch
"""

import os

import pandas as pd

# Map pipeline column  ->  Elasticsearch source field.
# Edit the right-hand side to match your index's actual field names.
FIELD_MAP = {
    "duration":      "dur",
    "src_bytes":     "sbytes",
    "dst_bytes":     "dbytes",
    "pkt_count":     "spkts",
    "failed_logins": "ct_state_ttl",   # placeholder; repoint to a real field
    "label":         "label",          # optional; drop if your data is unlabelled
}


def _client(host, api_key, username, password, verify_certs):
    """Build an Elasticsearch client (imported lazily so the rest of the
    project doesn't depend on the package being installed)."""
    try:
        from elasticsearch import Elasticsearch
    except ImportError as exc:
        raise ImportError(
            "The 'elasticsearch' package is required for the Elastic connector. "
            "Install it with:  pip install elasticsearch"
        ) from exc

    auth = {}
    if api_key:
        auth["api_key"] = api_key
    elif username and password:
        auth["basic_auth"] = (username, password)
    return Elasticsearch(host, verify_certs=verify_certs, **auth)


def fetch_alerts(
    host: str = None,
    index: str = None,
    api_key: str = None,
    username: str = None,
    password: str = None,
    size: int = 1000,
    query: dict = None,
    field_map: dict = None,
    verify_certs: bool = False,
) -> pd.DataFrame:
    """Query Elasticsearch and return a DataFrame in the pipeline's schema.

    Falls back to environment variables when arguments are omitted:
        ELASTIC_HOST, ELASTIC_INDEX, ELASTIC_API_KEY,
        ELASTIC_USER, ELASTIC_PASSWORD
    """
    host = host or os.getenv("ELASTIC_HOST", "https://localhost:9200")
    index = index or os.getenv("ELASTIC_INDEX", "unsw-nb15-*")
    api_key = api_key or os.getenv("ELASTIC_API_KEY")
    username = username or os.getenv("ELASTIC_USER")
    password = password or os.getenv("ELASTIC_PASSWORD")
    field_map = field_map or FIELD_MAP

    es = _client(host, api_key, username, password, verify_certs)
    body = {"size": size, "query": query or {"match_all": {}}}
    resp = es.search(index=index, body=body)

    rows = []
    for hit in resp["hits"]["hits"]:
        src = hit.get("_source", {})
        row = {}
        for col, field in field_map.items():
            if field in src:
                row[col] = src[field]
        if row:
            rows.append(row)

    if not rows:
        raise ValueError(
            f"No documents matched in index '{index}'. Check the index name, "
            f"the query, and that FIELD_MAP matches your field names."
        )

    df = pd.DataFrame(rows)

    # Coerce features to numeric; the model needs numbers.
    feature_cols = [c for c in field_map if c != "label" and c in df.columns]
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=feature_cols).reset_index(drop=True)

    # Synthesize identifiers the pipeline/dashboard expect.
    df.insert(0, "alert_id", [f"ES-{i:05d}" for i in range(len(df))])
    if "src_ip" not in df.columns:
        df["src_ip"] = "—"
    if "dst_ip" not in df.columns:
        df["dst_ip"] = "—"
    return df
