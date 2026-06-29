"""
generate_sample_data.py
------------------------
Creates a small, LABELLED set of synthetic security alerts so the whole
pipeline runs end-to-end out of the box. Replace this with real data
(e.g. UNSW-NB15) once you want meaningful numbers — keep the same column
names and the rest of the pipeline works unchanged.

Schema (one row = one alert):
    alert_id      unique id
    timestamp     ISO time
    src_ip        source IP
    dst_ip        destination IP
    proto         tcp/udp/icmp
    duration      connection duration (seconds)
    src_bytes     bytes sent
    dst_bytes     bytes received
    pkt_count     packets in the flow
    failed_logins failed auth attempts associated with the flow
    label         GROUND TRUTH: 1 = true positive (real threat), 0 = benign
"""

import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)


def _benign(n: int) -> pd.DataFrame:
    return pd.DataFrame({
        "proto": RNG.choice(["tcp", "udp"], size=n, p=[0.8, 0.2]),
        "duration": RNG.exponential(2.0, n).round(2),
        "src_bytes": RNG.normal(1200, 400, n).clip(50).astype(int),
        "dst_bytes": RNG.normal(3000, 900, n).clip(50).astype(int),
        "pkt_count": RNG.normal(40, 12, n).clip(1).astype(int),
        "failed_logins": RNG.choice([0, 1], size=n, p=[0.95, 0.05]),
        "label": 0,
    })


def _malicious(n: int) -> pd.DataFrame:
    # Threats look different: long/odd durations, lopsided byte counts,
    # bursts of packets, and clusters of failed logins (brute force).
    return pd.DataFrame({
        "proto": RNG.choice(["tcp", "udp", "icmp"], size=n, p=[0.5, 0.2, 0.3]),
        "duration": RNG.exponential(20.0, n).round(2),
        "src_bytes": RNG.normal(60000, 25000, n).clip(50).astype(int),
        "dst_bytes": RNG.normal(200, 150, n).clip(0).astype(int),
        "pkt_count": RNG.normal(600, 300, n).clip(1).astype(int),
        "failed_logins": RNG.choice([0, 5, 12, 30], size=n, p=[0.2, 0.3, 0.3, 0.2]),
        "label": 1,
    })


def make_dataset(n_benign: int = 950, n_malicious: int = 50) -> pd.DataFrame:
    """Imbalanced on purpose: real SOC traffic is mostly benign."""
    df = pd.concat([_benign(n_benign), _malicious(n_malicious)], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    df.insert(0, "alert_id", [f"ALRT-{i:05d}" for i in range(len(df))])
    df.insert(1, "timestamp",
              pd.date_range("2026-01-01", periods=len(df), freq="min")
              .strftime("%Y-%m-%dT%H:%M:%S"))
    df.insert(2, "src_ip", [f"10.0.{RNG.integers(0,255)}.{RNG.integers(1,254)}"
                            for _ in range(len(df))])
    df.insert(3, "dst_ip", [f"192.168.1.{RNG.integers(1,254)}"
                            for _ in range(len(df))])
    return df


if __name__ == "__main__":
    out = "data/sample_alerts.csv"
    make_dataset().to_csv(out, index=False)
    print(f"Wrote labelled sample to {out}")
