"""
report.py
---------
Generates an analyst-facing triage report per run — the "reporting" half of
"automation of false positive analysis AND REPORTING using AI".

Output: a markdown file with run summary, detection quality (when labels
exist), the top escalated alerts with rationales, and tuning notes.
"""

from datetime import datetime, timezone

import pandas as pd

from src.metrics import compute_metrics


def build_report(df: pd.DataFrame, source_name: str = "unknown",
                 contamination: float | None = None) -> str:
    m = compute_metrics(df)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lanes = df["final_decision"].value_counts()

    lines = [
        "# Alert Triage Report",
        "",
        f"- **Generated:** {now}",
        f"- **Source:** {source_name}",
        f"- **Alerts processed:** {m['alerts_total']:,}",
    ]
    if contamination is not None:
        lines.append(f"- **Stage 1 contamination setting:** {contamination}")
    lines += [
        "",
        "## Outcome",
        "",
        "| Lane | Alerts | Share |",
        "|---|---|---|",
    ]
    for lane, n in lanes.items():
        lines.append(f"| {lane} | {n:,} | {n/len(df):.1%} |")

    lines += [
        "",
        f"**Analyst workload removed: {m['analyst_workload_reduction']:.0%}** "
        f"({m['alerts_total'] - m['flagged_for_human']:,} of "
        f"{m['alerts_total']:,} alerts resolved without human time).",
        "",
    ]

    if m["has_labels"]:
        lines += [
            "## Detection quality (vs ground truth)",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Precision | {m['precision']} |",
            f"| Recall | {m['recall']} |",
            f"| F1 | {m['f1']} |",
            f"| False-positive rate | {m['false_positive_rate']} |",
            f"| TP / FP / FN / TN | {m['true_positives']} / {m['false_positives']}"
            f" / {m['false_negatives']} / {m['true_negatives']} |",
            "",
        ]
        if m["false_negatives"]:
            lines.append(f"> ⚠ {m['false_negatives']} real threat(s) were "
                         "auto-suppressed. Consider lowering the suppress "
                         "threshold or raising contamination.")
        lines.append("")
    else:
        lines += ["## Detection quality", "",
                  "_No ground-truth labels in this source; precision/recall "
                  "not computable. Operational metrics above still apply._", ""]

    # Top escalations with rationales — what an analyst reads first.
    esc = df[df["final_decision"].isin(["escalate", "true_positive"])]
    esc = esc.sort_values("anomaly_score", ascending=False).head(10)
    lines += ["## Top escalated alerts", ""]
    if len(esc):
        lines += ["| Alert | Score | Source | Rationale |", "|---|---|---|---|"]
        for _, r in esc.iterrows():
            rat = str(r.get("rationale", ""))[:90]
            lines.append(f"| {r['alert_id']} | {r['anomaly_score']:.3f} "
                         f"| {r.get('source','')} | {rat} |")
    else:
        lines.append("_None this run._")
    lines.append("")

    review_n = int((df["final_decision"] == "needs_review").sum())
    lines += [
        "## Notes",
        "",
        f"- {review_n:,} alert(s) await analyst review "
        "(see outputs/tickets.json).",
        "- Verdicts marked `heuristic_fallback` were produced offline; set "
        "ANTHROPIC_API_KEY to enable Claude API classification.",
        "",
    ]
    return "\n".join(lines)


def write_report(df: pd.DataFrame, path: str = "outputs/triage_report.md",
                 **kwargs) -> str:
    text = build_report(df, **kwargs)
    with open(path, "w") as fh:
        fh.write(text)
    return path
