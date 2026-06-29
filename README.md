![AI Alert Triage](banner.png)

# AI Alert Triage

**A two-stage security-alert triage system that automatically suppresses false-positive noise so analysts only see the alerts that matter.** A cheap Isolation Forest pre-filter handles the obvious cases; the **Claude API** makes the judgement call on the ambiguous ones.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Powered by Claude](https://img.shields.io/badge/AI%20triage-Claude%20API-D97757)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)

Built as a portfolio project for SOC / GRC work — specifically the task of *"automating false-positive analysis and reporting using AI."*

---

## Powered by the Claude API

The intelligence in this pipeline is **Anthropic's Claude API**. Stage 1 is a fast statistical filter that clears the easy cases, but the alerts in the ambiguous middle — the ones a human would actually have to stop and think about — are sent to Claude, which returns a structured verdict (`true_positive` / `false_positive` / `needs_review`), a confidence score, a one-line rationale, and a recommended action.

This is deliberate: running an LLM on *every* alert would be slow and expensive, so the cheap pre-filter exists to spend the Claude API budget only where human-level judgement is genuinely needed. That is what "AI triage" means here — using the model precisely, not indiscriminately.

> The model is configurable via `TRIAGE_MODEL` in your `.env` (default `claude-haiku-4-5` for cheap, high-volume triage; switch to `claude-sonnet-4-6` for stronger per-alert reasoning).

---

## Why this exists

A real SOC drowns in alerts, and most are false positives. The scarce resource is analyst attention. This pipeline spends a cheap model on the easy calls, reserves the Claude API for the genuinely ambiguous alerts, and then reports how much human work it removed.

## How it works

```
   alerts.csv
       │
       ▼
┌─────────────────────────────┐
│ STAGE 1  Isolation Forest    │   normalized anomaly score + hard rules
│ + rules (cheap, every alert) │
└─────────────────────────────┘
       │ routes each alert into one of three lanes
       ├─ auto_suppress  → likely false positive · no human, no LLM
       ├─ escalate       → clearly anomalous · straight to a ticket
       └─ review         → ambiguous … handed to Stage 2
                              │
                              ▼
              ┌─────────────────────────────┐
              │ STAGE 2  Claude API          │  verdict + confidence +
              │ (only the ambiguous alerts)  │  rationale + action, as JSON
              └─────────────────────────────┘
       │
       ▼
   final_decision per alert
       ├─ metrics report      (outputs/metrics.json)
       ├─ triaged alerts       (outputs/triaged_alerts.csv)
       └─ ticket-ready JSON    (outputs/tickets.json)  ← feeds the ticketing project
```

## Results

On a 1,000-alert labelled sample (5% true threats), running with the offline **heuristic fallback** (no API key):

| Metric | Value |
|---|---|
| Recall (threats caught) | 1.00 |
| Precision | 0.50 |
| False-positive rate | 0.05 |
| FP auto-suppression rate | 0.53 |
| Analyst workload reduction | 0.90 |

Read: every threat was caught, ~53% of benign alerts were auto-suppressed without a human, and ~90% of all alerts were resolved without analyst time. Precision is the metric the **Claude API** path is designed to lift — the model removes false alarms the cheap filter can't.

> These numbers come from **synthetic** data and the offline fallback. Swap in a real labelled dataset (e.g. UNSW-NB15) and set an API key for meaningful results — see below.

## Tech stack

Python · scikit-learn (Isolation Forest) · **Claude API (Anthropic)** · pandas · Streamlit

## Quickstart

```bash
# 1. Install
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. (Optional) enable the real Claude API triage path
cp .env.example .env       # then edit .env and paste your Anthropic API key
#    Without a key, the pipeline runs using an offline heuristic fallback.

# 3. Generate the sample data and run
python src/generate_sample_data.py
python -m src.pipeline

# 4. Or use the dashboard
streamlit run app/dashboard.py
```

Outputs land in `outputs/` (gitignored): a metrics report, the triaged alert table, and ticket-ready JSON.

### Getting a Claude API key

Create one at the [Anthropic Console](https://console.anthropic.com), then put it in your local `.env` file as `ANTHROPIC_API_KEY`. The `.env` file is gitignored, so your key never reaches GitHub — only `.env.example` (a placeholder template) is committed.

## Using real data

The pipeline expects these columns: `duration, src_bytes, dst_bytes, pkt_count, failed_logins` (numeric features) plus `label` (1 = threat, 0 = benign) for scoring. Point it at any CSV with those columns:

```bash
python -c "from src.pipeline import run_pipeline; run_pipeline('data/your_data.csv')"
```

For real numbers, the **UNSW-NB15** intrusion dataset is a good fit — it has labelled flows with overlapping features. Map its columns to the names above.

## Project layout

```
ai-alert-triage/
├── src/
│   ├── generate_sample_data.py   synthetic labelled alerts
│   ├── stage1_prefilter.py       Isolation Forest + routing rules
│   ├── stage2_classifier.py      Claude API classifier (+ offline fallback)
│   ├── pipeline.py               orchestrates stage 1 → stage 2 → reports
│   ├── metrics.py                precision / recall / FP-suppression
│   └── ticketing.py              ticket-ready JSON output
├── app/dashboard.py              Streamlit UI
├── data/                         sample data
└── outputs/                      generated reports (gitignored)
```

## Roadmap

- [ ] Run on UNSW-NB15 and publish real precision / recall.
- [ ] Tune the Stage 1 review band to balance Claude API cost vs precision.
- [ ] Wire `outputs/tickets.json` into a ticketing tool via REST API.
- [ ] Add a control-mapping write-up linking detections to NIST CSF 2.0.

## Part of a portfolio

One of three linked security projects:
1. **ai-alert-triage** (this repo) — AI false-positive automation with the Claude API
2. **security-control-mapping** — NIST CSF 2.0 / ISO 27001 / PCI DSS mapping
3. **security-ticket-workflow** — ServiceNow / Jira incident workflow

---

<sub>This project uses the Claude API by Anthropic for AI-driven alert classification. Claude is a trademark of Anthropic.</sub>
