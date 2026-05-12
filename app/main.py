"""
SOC Sentinel — main landing page.

Run with:
    streamlit run app/main.py
"""
import sys
from pathlib import Path

# Make project importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from app.style import (
    set_page_config,
    render_sidebar_header,
    render_sidebar_footer,
    format_compact,
)
from app.data import get_warehouse_stats, get_headline_kpis


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Overview", page_icon="🛡️")
render_sidebar_header()

# ---------------------------------------------------------------------
# Hero
# ---------------------------------------------------------------------

st.markdown(
    """
    <div style="padding: 1rem 0;">
        <h1 style="margin:0; color:#e6edf3;">🛡️ SOC Sentinel</h1>
        <p style="color:#a3b1c2; font-size:1.1em; margin-top:0.3rem;">
            ML-powered threat triage for security operations centers.
            CICIDS2017 dataset · 2.83M events · 3 ML models in fusion.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------
# Warehouse health
# ---------------------------------------------------------------------

with st.spinner("Loading warehouse stats..."):
    stats = get_warehouse_stats()
    kpis = get_headline_kpis()

# ---------------------------------------------------------------------
# Top row — headline numbers
# ---------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Events Analyzed",
        format_compact(kpis["total_events"]),
        help="Total network flows in the warehouse",
    )

with col2:
    st.metric(
        "Attacks Detected",
        format_compact(kpis["attack_count"]),
        delta=f"{kpis['attack_count'] / kpis['total_events'] * 100:.1f}% of all events",
        delta_color="off",
        help="Events with attack_family != Benign",
    )

with col3:
    st.metric(
        "Critical Alerts",
        format_compact(kpis["critical_count"]),
        delta=f"{kpis['critical_count'] / kpis['total_events'] * 100:.1f}% prioritized",
        delta_color="inverse",
        help="ML priority score ≥ 0.75",
    )

with col4:
    st.metric(
        "Unique Source IPs",
        format_compact(kpis["unique_src"]),
        help="Distinct attacking/originating endpoints",
    )

# ---------------------------------------------------------------------
# Capabilities walkthrough
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Dashboard Capabilities")

col_a, col_b = st.columns(2)

with col_a:
    st.markdown(
        """
        ### 📊 Analytics Pages
        - **Summary** — KPIs, attack family distribution, priority breakdown
        - **Timeline** — chronological attack volume by family
        - **Geography** — world map of attacker origins
        - **Heatmap** — hour-of-day × day-of-week attack patterns
        - **Alerts** — sortable queue of top-priority events
        """
    )

with col_b:
    st.markdown(
        """
        ### 🧠 ML Architecture
        - **Random Forest** — binary attack/benign classifier
        - **XGBoost** — 9-class attack family classifier
        - **Isolation Forest** — anomaly detector for novel threats
        - **Priority Fusion** — combines all three signals with severity context
        - **Live updates** — fact table auto-refreshes via ETL pipeline
        """
    )

# ---------------------------------------------------------------------
# Warehouse health diagnostic
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Warehouse Health")

col1, col2, col3, col4 = st.columns(4)
tables = stats["tables"]

with col1:
    st.metric("Fact Events", format_compact(tables.get("fact_security_event", 0)))
with col2:
    st.metric("Distinct Assets", format_compact(tables.get("dim_asset", 0)))
with col3:
    st.metric("Distinct Ports", format_compact(tables.get("dim_port", 0)))
with col4:
    st.metric("Attack Types", tables.get("dim_attack_type", 0))

if stats.get("latest_scored_at"):
    st.caption(f"Latest ML scoring: **{stats['latest_scored_at']}** (Model: phase1-v1.0)")
else:
    st.warning("No ML scoring detected. Run `python -m src.ml.score` to populate priorities.")

# ---------------------------------------------------------------------
# Navigation hint
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Explore the dashboard")

nav_col1, nav_col2, nav_col3 = st.columns(3)

with nav_col1:
    st.markdown(
        """
        ### 📊 [Summary](Summary)
        Operational KPIs, priority distribution donut, and per-family alert quality scores.
        
        ### 📈 [Timeline](Timeline)
        Chronological 5-day attack progression with per-family filtering.
        """
    )

with nav_col2:
    st.markdown(
        """
        ### 🌍 [Geography](Geography)
        World map of attacker origins with attack flow arcs to the lab network.
        
        ### 🔥 [Heatmap](Heatmap)
        Hour × day attack pattern revealing the 100% working-hours signature.
        """
    )

with nav_col3:
    st.markdown(
        """
        ### 🚨 [Alerts](Alerts)
        Operational queue of top-priority events with rich filtering and CSV export.
        
        ### 🚧 Coming in Phase 2
        Insider threat analytics from CERT r4.2 dataset (Weeks 9-11).
        """
    )

st.markdown("---")
st.caption(
    "💡 SOC Sentinel is a portfolio capstone project demonstrating end-to-end "
    "data warehousing, ML model fusion, and dashboard development on the CICIDS2017 dataset."
)

render_sidebar_footer()