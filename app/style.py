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
    """
    Render the SOC Sentinel branded sidebar header with
    section labels for Network Threats and Insider Threats.
    """
    st.sidebar.markdown(
        """
        <style>
        /* Hide default page nav so we render our own grouped version */
        [data-testid="stSidebarNav"] {
            display: none;
        }
        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.5rem 0 0.8rem 0;
            margin-bottom: 0.8rem;
            border-bottom: 1px solid #2a2f37;
        }
        .sidebar-brand-text {
            font-size: 1.4em;
            font-weight: 700;
            color: #5a8da4;
            letter-spacing: -0.02em;
        }
        .sidebar-brand-sub {
            color: #7d8a98;
            font-size: 0.75em;
            margin-top: -0.2rem;
        }
        .sidebar-section-label {
            color: #7d8a98;
            font-size: 0.7em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin: 1.1rem 0 0.4rem 0;
            padding: 0;
        }
        .sidebar-nav-link {
            color:#7d8a98 !important;
            display: block;
            text-decoration: none;
            padding: 0.4rem 0.7rem;
            border-radius: 8px;
            margin: 0.1rem 0;
            transition: background 0.15s ease;
        }
        .sidebar-nav-link:hover {
            background: rgba(90, 141, 164, 0.15);
            text-decoration: none;
        }
        </style>
        <div class="sidebar-brand">
            <span style="font-size: 1.5em;">🛡️</span>
            <div>
                <div class="sidebar-brand-text">SOC Sentinel</div>
                <div class="sidebar-brand-sub">Unified Threat Analytics</div>
            </div>
        </div>
        <a href="/" target="_self" class="sidebar-nav-link">main</a>

        <p class="sidebar-section-label">Network Threats</p>
        <a href="/Summary" target="_self" class="sidebar-nav-link">📊 Summary</a>
        <a href="/Timeline" target="_self" class="sidebar-nav-link">📈 Timeline</a>
        <a href="/Geography" target="_self" class="sidebar-nav-link">🌍 Geography</a>
        <a href="/Heatmap" target="_self" class="sidebar-nav-link">🔥 Heatmap</a>
        <a href="/Alerts" target="_self" class="sidebar-nav-link">🚨 Alerts</a>

        <p class="sidebar-section-label">Insider Threats</p>
        <a href="/User_Risk" target="_self" class="sidebar-nav-link">🕵️ User Risk</a>
        <a href="/Scenarios" target="_self" class="sidebar-nav-link">🎭 Scenarios</a>
        <a href="/User_Drilldown" target="_self" class="sidebar-nav-link">🔬 User Drilldown</a>
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
            <p>Data source 1: CICIDS2017</p>
            <p>Data source 2: CERT r4.2</p>
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