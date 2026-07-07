"""
convert_unsw.py
---------------
Convert a UNSW-NB15 dataset file into the schema this pipeline expects
(duration, src_bytes, dst_bytes, pkt_count, label).

Handles both formats:
  * RAW source files (UNSW-NB15_1..4.csv) — 49 columns, NO header row.
  * Preprocessed sets (UNSW_NB15_training-set.csv) — named header.

UNSW-NB15 has no 'failed_logins' field, so it's simply omitted; the pipeline
now scores on whatever features are present.

Usage:
  python tools/convert_unsw.py UNSW-NB15_1.csv -o data/unsw_ready.csv --sample 60000
"""

import argparse
import pandas as pd

RAW_COLS = ['srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
 'sttl','dttl','sloss','dloss','service','Sload','Dload','Spkts','Dpkts','swin','dwin',
 'stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len','Sjit','Djit','Stime',
 'Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports','ct_state_ttl',
 'ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd','ct_srv_src','ct_srv_dst','ct_dst_ltm',
 'ct_src_ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label']


def load(path: str) -> pd.DataFrame:
    """Detect raw-vs-preprocessed by peeking at the first line."""
    with open(path, "r", errors="ignore") as fh:
        first = fh.readline().lower()
    is_raw = ("sbytes" not in first) and ("dur," not in first)
    if is_raw:
        return pd.read_csv(path, header=None, names=RAW_COLS, low_memory=False)
    return pd.read_csv(path, low_memory=False)


def to_pipeline_schema(df: pd.DataFrame) -> pd.DataFrame:
    cols = {c.lower(): c for c in df.columns}

    def col(*names):
        for n in names:
            if n.lower() in cols:
                return df[cols[n.lower()]]
        return None

    out = pd.DataFrame()
    out["duration"]  = pd.to_numeric(col("dur"), errors="coerce")
    out["src_bytes"] = pd.to_numeric(col("sbytes"), errors="coerce")
    out["dst_bytes"] = pd.to_numeric(col("dbytes"), errors="coerce")
    spkts = pd.to_numeric(col("Spkts", "spkts"), errors="coerce").fillna(0)
    dpkts = pd.to_numeric(col("Dpkts", "dpkts"), errors="coerce").fillna(0)
    out["pkt_count"] = spkts + dpkts

    # richer signal — these help Isolation Forest separate attacks
    for pipe_name, *src_names in [
        ("src_ttl", "sttl"), ("dst_ttl", "dttl"),
        ("src_load", "Sload", "sload"), ("dst_load", "Dload", "dload"),
        ("state_ttl_count", "ct_state_ttl"),
    ]:
        s = col(*src_names)
        if s is not None:
            out[pipe_name] = pd.to_numeric(s, errors="coerce").fillna(0)

    out["label"] = pd.to_numeric(col("label"), errors="coerce").fillna(0).astype(int)

    # nice-to-haves for the dashboard, if present
    if col("srcip") is not None:
        out["src_ip"] = col("srcip").astype(str)
    if col("dstip") is not None:
        out["dst_ip"] = col("dstip").astype(str)

    out = out.dropna(subset=["duration", "src_bytes", "dst_bytes"]).reset_index(drop=True)
    out.insert(0, "alert_id", [f"UNSW-{i:06d}" for i in range(len(out))])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="data/unsw_ready.csv")
    ap.add_argument("--sample", type=int, default=0,
                    help="stratified sample size (keeps the attack ratio); 0 = all rows")
    args = ap.parse_args()

    df = to_pipeline_schema(load(args.input))

    if args.sample and args.sample < len(df):
        frac = args.sample / len(df)
        df = (df.groupby("label", group_keys=False)
                .sample(frac=frac, random_state=42)
                .reset_index(drop=True))

    df.to_csv(args.output, index=False)
    threats = int(df["label"].sum())
    print(f"Wrote {len(df):,} rows to {args.output} "
          f"({threats:,} threats, {threats/len(df):.1%})")


if __name__ == "__main__":
    main()
