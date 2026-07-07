"""
theme.py
--------
One palette, shared by the banner, the dashboard, and the charts, so the whole
project looks like a single designed thing. Colours match banner.svg.
"""

PALETTE = {
    "bg":     "#0B1220",   # deep SOC slate
    "panel":  "#0E1729",   # card / panel
    "ink":    "#E7EEF7",   # primary text
    "mute":   "#7C8DA6",   # secondary text
    "grid":   "#1C2940",   # gridlines / borders
    "cyan":   "#38BDF8",   # AI / accent
    "green":  "#34D399",   # suppress / clear
    "amber":  "#F5B445",   # review
    "red":    "#F0584F",   # escalate / true positive
    "grey":   "#48586E",   # unclassified
}

# Map a final_decision value to its lane colour.
DECISION_COLORS = {
    "auto_suppress":  PALETTE["green"],
    "false_positive": PALETTE["green"],
    "needs_review":   PALETTE["amber"],
    "review":         PALETTE["amber"],
    "escalate":       PALETTE["red"],
    "true_positive":  PALETTE["red"],
}


def apply_dark(fig):
    """Apply the project's dark theme to any Plotly figure."""
    p = PALETTE
    fig.update_layout(
        paper_bgcolor=p["bg"],
        plot_bgcolor=p["bg"],
        font=dict(color=p["ink"], family="DejaVu Sans, Arial, sans-serif", size=13),
        margin=dict(l=40, r=20, t=50, b=40),
        title_font=dict(size=16, color=p["ink"]),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=p["mute"])),
        colorway=[p["cyan"], p["green"], p["amber"], p["red"]],
    )
    fig.update_xaxes(gridcolor=p["grid"], zerolinecolor=p["grid"],
                     linecolor=p["grid"], tickfont=dict(color=p["mute"]))
    fig.update_yaxes(gridcolor=p["grid"], zerolinecolor=p["grid"],
                     linecolor=p["grid"], tickfont=dict(color=p["mute"]))
    return fig
