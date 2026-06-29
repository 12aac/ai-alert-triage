"""
stage2_classifier.py
--------------------
STAGE 2 — the AI judgement call.

Only the ambiguous 'review' alerts from Stage 1 reach here. Each one is sent
to the Claude API, which returns a structured verdict:

    {
      "verdict": "true_positive" | "false_positive" | "needs_review",
      "confidence": 0.0 - 1.0,
      "rationale": "one sentence",
      "recommended_action": "short next step"
    }

DESIGN NOTE — graceful fallback:
If no ANTHROPIC_API_KEY is set, the module falls back to a deterministic
heuristic so the pipeline still runs end-to-end (useful for demos and CI
without spending credits). The real value is the LLM path; the fallback just
keeps the project runnable.
"""

import json
import os

from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("TRIAGE_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = (
    "You are a SOC tier-1 triage assistant. Given one security alert, decide "
    "whether it is a true positive, a false positive, or genuinely needs human "
    "review. Be conservative: when a real threat is plausible, do NOT mark it a "
    "false positive. Respond with ONLY a JSON object and no other text, with keys: "
    "verdict (one of 'true_positive','false_positive','needs_review'), "
    "confidence (number 0-1), rationale (one sentence), "
    "recommended_action (short imperative)."
)


def _alert_to_text(alert: dict) -> str:
    fields = ["proto", "duration", "src_bytes", "dst_bytes",
              "pkt_count", "failed_logins", "anomaly_score"]
    lines = [f"{k}: {alert.get(k)}" for k in fields if k in alert]
    return "Security alert:\n" + "\n".join(lines)


def _heuristic(alert: dict) -> dict:
    """Fallback used only when no API key is configured."""
    score = float(alert.get("anomaly_score", 0))
    fails = int(alert.get("failed_logins", 0))
    if fails >= 5 or score >= 0.6:
        return {"verdict": "true_positive", "confidence": 0.6,
                "rationale": "Elevated anomaly score or repeated failed logins.",
                "recommended_action": "Open a ticket for analyst review."}
    if score <= 0.3:
        return {"verdict": "false_positive", "confidence": 0.6,
                "rationale": "Low anomaly score, traffic resembles baseline.",
                "recommended_action": "Suppress and log."}
    return {"verdict": "needs_review", "confidence": 0.5,
            "rationale": "Indicators are mixed.",
            "recommended_action": "Escalate to tier-2 for a closer look."}


def classify_alert(alert: dict, client=None) -> dict:
    """Classify a single alert. Returns the verdict dict described above."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        result = _heuristic(alert)
        result["source"] = "heuristic_fallback"
        return result

    # Lazy import so the heuristic path has no hard dependency on the SDK.
    if client is None:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=300,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _alert_to_text(alert)}],
        )
        text = "".join(block.text for block in msg.content
                       if getattr(block, "type", None) == "text").strip()
        # Strip accidental code fences before parsing.
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        result["source"] = MODEL
        return result
    except Exception as exc:  # network, parse, rate-limit, etc.
        result = _heuristic(alert)
        result["source"] = f"fallback_after_error:{type(exc).__name__}"
        return result


if __name__ == "__main__":
    demo = {"proto": "tcp", "duration": 45.2, "src_bytes": 90000,
            "dst_bytes": 120, "pkt_count": 800, "failed_logins": 12,
            "anomaly_score": 0.72}
    print(json.dumps(classify_alert(demo), indent=2))
