# Security Notes

This is a **portfolio / lab project** intended to run locally against lab or
research data. It is not hardened for production use. Known assumptions and
limitations, stated openly:

## Scope & assumptions
- Designed for **local execution** (analyst workstation or lab VM). The
  Streamlit dashboard has **no authentication** — do not expose port 8501
  beyond localhost or a trusted lab network.
- Input data (CSV uploads, SIEM query results) is **assumed trusted**. There
  is basic schema validation but no hard size limits or content sanitization.

## Secrets
- API keys and credentials are read from environment variables / a local
  `.env` file, which is **gitignored** — never commit `.env`.
- If a key is ever pushed by accident, **rotate it immediately**; git history
  preserves it.

## TLS
- The Elasticsearch connector **verifies TLS certificates by default**
  (`verify_certs=True`). For lab clusters with self-signed certificates you
  must explicitly opt out with `verify_certs=False`, accepting the
  man-in-the-middle risk on that connection.

## Data governance
- Stage 2 sends alert feature values to the **Anthropic Claude API**, and the
  ticket-push connectors send alert summaries to **Jira / ServiceNow**. Before
  using real organizational data, confirm this is acceptable under your data
  handling policies.

## Hardening before any production use (non-exhaustive)
- Add authentication in front of the dashboard.
- Enforce upload size limits and strict schema validation.
- Pin and scan dependencies (e.g. `pip-audit`, Dependabot).
- Add rate limiting / cost caps on API calls.

## Reporting
Found a vulnerability? Open a GitHub issue or email the maintainer.
