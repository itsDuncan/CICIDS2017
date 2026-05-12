"""
Shared styling and formatting helpers for the SOC Sentinel dashboard.
"""
from typing import Optional

import streamlit as st


# ---------------------------------------------------------------------
# Color palette — consistent across all pages
# ---------------------------------------------------------------------

COLORS = {
    "critical": "#e63946",   # red — definitive threats
    "high":     "#f4a261",   # orange — high-priority alerts
    "medium":   "#e9c46a",   # yellow — medium alerts
    "low":      "#90c8a4",   # green — low alerts
    "info":     "#5a8da4",   # blue — informational
    "benign":   "#6a7a87",   # gray — benign baseline
    "neutral":  "#a3b1c2",
}

ATTACK_FAMILY_COLORS = {
    "Benign":         "#6a7a87",
    "DoS":            "#e63946",
    "DDoS":           "#a8324a",
    "Brute Force":    "#f4a261",
    "Reconnaissance": "#e9c46a",
    "Web Attack":     "#f08080",
    "Botnet":         "#9b5de5",
    "Infiltration":   "#c1121f",
    "Exploit":        "#780000",
    "Unlabeled":      "#cbd5e1",
}

SEVERITY_BADGE_HTML = {
    "critical": '<span style="background:#e63946;color:white;padding:2px 8px;border-radius:4px;font-size:0.85em;">CRITICAL</span>',
    "high":     '<span style="background:#f4a261;color:white;padding:2px 8px;border-radius:4px;font-size:0.85em;">HIGH</span>',
    "medium":   '<span style="background:#e9c46a;color:black;padding:2px 8px;border-radius:4px;font-size:0.85em;">MEDIUM</span>',
    "low":      '<span style="background:#90c8a4;color:black;padding:2px 8px;border-radius:4px;font-size:0.85em;">LOW</span>',
    "info":     '<span style="background:#5a8da4;color:white;padding:2px 8px;border-radius:4px;font-size:0.85em;">INFO</span>',
}


# ---------------------------------------------------------------------
# Page configuration helper
# ---------------------------------------------------------------------

def set_page_config(page_title: str, page_icon: str = "🛡️"):
    """Standard page config used by every page."""
    st.set_page_config(
        page_title=f"SOC Sentinel — {page_title}",
        page_icon=page_icon,
        layout="wide",
        initial_sidebar_state="expanded",
    )


# ---------------------------------------------------------------------
# KPI card — used on summary page
# ---------------------------------------------------------------------

def kpi_card(
    label: str,
    value: str,
    delta: Optional[str] = None,
    delta_color: str = "normal",
    help_text: Optional[str] = None,
):
    """Styled KPI metric. Wraps st.metric for consistency."""
    st.metric(
        label=label,
        value=value,
        delta=delta,
        delta_color=delta_color,
        help=help_text,
    )


# ---------------------------------------------------------------------
# Sidebar header — consistent branding
# ---------------------------------------------------------------------

def render_sidebar_header():
    """Render branded sidebar header. Call from every page."""
    st.sidebar.markdown(
        """
        <div style="text-align:center; padding: 0.5rem 0 1rem 0;">
            <h2 style="color:#e63946; margin:0;">🛡️ SOC Sentinel</h2>
            <p style="color:#a3b1c2; margin:0; font-size:0.85em;">
                Phase 1 · Network Threat Analytics
            </p>
        </div>
        <hr style="margin: 0.5rem 0;">
        """,
        unsafe_allow_html=True,
    )


def render_sidebar_footer(rows_loaded: Optional[int] = None,
                          last_scored: Optional[str] = None):
    """Render footer with warehouse stats."""
    st.sidebar.markdown("<hr>", unsafe_allow_html=True)
    st.sidebar.markdown(
        """
        <div style="font-size:0.75em; color:#7d8a98; padding-top:1rem;">
            <p>Data source: CICIDS2017</p>
            <p>Phase 2 (CERT Insider Threat) coming soon</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------

def format_number(n: int) -> str:
    """Format large numbers with commas: 2830743 → '2,830,743'."""
    return f"{n:,}"


def format_compact(n: int) -> str:
    """Compact format for big numbers: 2830743 → '2.83M'."""
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def format_pct(n: float, decimals: int = 1) -> str:
    """Format proportion as percentage: 0.1397 → '14.0%'."""
    return f"{n * 100:.{decimals}f}%"