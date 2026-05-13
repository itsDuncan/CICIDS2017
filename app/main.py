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
# Custom CSS for card components
# ---------------------------------------------------------------------

st.markdown(
    """
    <style>
    .kpi-card {
        background: linear-gradient(145deg, #1c2128, #181c22);
        border: 1px solid #2a2f37;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        height: 100%;
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #5a8da4;
        transform: translateY(-2px);
    }
    .kpi-card .kpi-label {
        color: #a3b1c2;
        font-size: 0.85em;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin: 0;
    }
    .kpi-card .kpi-value {
        color: #e6edf3;
        font-size: 2.3em;
        font-weight: 700;
        margin: 0.2rem 0;
        line-height: 1.1;
    }
    .kpi-card .kpi-delta {
        color: #5a8da4;
        font-size: 0.85em;
        margin: 0;
    }
    .kpi-card.critical .kpi-delta {
        color: #e63946;
    }
    .kpi-card .kpi-icon {
        font-size: 1.5em;
        margin-bottom: 0.5rem;
        opacity: 0.8;
    }

    .nav-card-link {
    text-decoration: none;
    display: block;
    color: inherit;
    }
    .nav-card-link:hover {
        text-decoration: none;
    }
    .nav-card {
        background: linear-gradient(145deg, #1c2128, #181c22);
        border: 1px solid #2a2f37;
        border-radius: 12px;
        padding: 1.4rem 1.5rem;
        margin-bottom: 0.9rem;
        height: 100%;
        transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
        cursor: pointer;
    }
    .nav-card-link:hover .nav-card {
        border-color: #e63946;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(230, 57, 70, 0.15);
    }
    .nav-card h3 {
        color: #e6edf3;
        margin: 0 0 0.4rem 0;
        font-size: 1.15em;
    }
    .nav-card-link:hover .nav-card h3 {
        color: #f4a261;
    }
    .nav-card p {
        color: #a3b1c2;
        margin: 0;
        font-size: 0.9em;
        line-height: 1.5;
    }
    .nav-card .nav-icon {
        font-size: 1.6em;
        margin-bottom: 0.4rem;
        display: block;
    }
    .nav-card.coming-soon {
        border-style: dashed;
        opacity: 0.7;
        cursor: default;
    }
    .nav-card-link.disabled {
        pointer-events: none;
    }

    .health-card {
        background: rgba(28, 33, 40, 0.6);
        border: 1px solid #2a2f37;
        border-radius: 10px;
        padding: 1rem 1.25rem;
        text-align: center;
    }
    .health-card .health-label {
        color: #a3b1c2;
        font-size: 0.8em;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin: 0;
    }
    .health-card .health-value {
        color: #e6edf3;
        font-size: 1.8em;
        font-weight: 700;
        margin: 0.2rem 0 0 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


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
# Top row — headline KPI cards
# ---------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

total = kpis["total_events"]

with col1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">📊</div>
            <p class="kpi-label">Events Analyzed</p>
            <p class="kpi-value">{format_compact(total)}</p>
            <p class="kpi-delta">Total network flows</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    attacks_pct = kpis['attack_count'] / total * 100
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">⚔️</div>
            <p class="kpi-label">Attacks Detected</p>
            <p class="kpi-value">{format_compact(kpis['attack_count'])}</p>
            <p class="kpi-delta">{attacks_pct:.1f}% of all events</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    critical_pct = kpis['critical_count'] / total * 100
    st.markdown(
        f"""
        <div class="kpi-card critical">
            <div class="kpi-icon">🚨</div>
            <p class="kpi-label">Critical Alerts</p>
            <p class="kpi-value">{format_compact(kpis['critical_count'])}</p>
            <p class="kpi-delta">{critical_pct:.1f}% prioritized</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">🌐</div>
            <p class="kpi-label">Unique Source IPs</p>
            <p class="kpi-value">{format_compact(kpis['unique_src'])}</p>
            <p class="kpi-delta">Distinct endpoints observed</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------
# Insider Threat
# ---------------------------------------------------------------------

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("---")
st.subheader("Insider Threat (CERT r4.2)")

with st.spinner("Loading insider threat stats..."):
    from app.data import get_phase2_kpis
    p2 = get_phase2_kpis()

p2_col1, p2_col2, p2_col3, p2_col4 = st.columns(4)

with p2_col1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">👥</div>
            <p class="kpi-label">Users Analyzed</p>
            <p class="kpi-value">{format_compact(p2['total_users'])}</p>
            <p class="kpi-delta">{format_compact(p2['total_events'])} activity events</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with p2_col2:
    st.markdown(
        f"""
        <div class="kpi-card critical">
            <div class="kpi-icon">🚩</div>
            <p class="kpi-label">Flagged Users</p>
            <p class="kpi-value">{p2['flagged_users']}</p>
            <p class="kpi-delta">{p2['flagged_correctly']} confirmed malicious</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with p2_col3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">🎯</div>
            <p class="kpi-label">Recall</p>
            <p class="kpi-value">{p2['recall']}%</p>
            <p class="kpi-delta">{p2['flagged_correctly']} of {p2['malicious_truth']} caught</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with p2_col4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">✅</div>
            <p class="kpi-label">Precision</p>
            <p class="kpi-value">{p2['precision']}%</p>
            <p class="kpi-delta">Of flagged users</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------
# Capabilities walkthrough
# ---------------------------------------------------------------------

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("---")
st.subheader("Dashboard capabilities")

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
# Warehouse health
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Warehouse health")

col1, col2, col3, col4 = st.columns(4)
tables = stats["tables"]

with col1:
    st.markdown(
        f"""
        <div class="health-card">
            <p class="health-label">Fact Events</p>
            <p class="health-value">{format_compact(tables.get('fact_security_event', 0))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with col2:
    st.markdown(
        f"""
        <div class="health-card">
            <p class="health-label">Distinct Assets</p>
            <p class="health-value">{format_compact(tables.get('dim_asset', 0))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with col3:
    st.markdown(
        f"""
        <div class="health-card">
            <p class="health-label">Distinct Ports</p>
            <p class="health-value">{format_compact(tables.get('dim_port', 0))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with col4:
    st.markdown(
        f"""
        <div class="health-card">
            <p class="health-label">Attack Types</p>
            <p class="health-value">{tables.get('dim_attack_type', 0)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

if stats.get("latest_scored_at"):
    st.caption(f"Latest ML scoring: **{stats['latest_scored_at']}** (Model: phase1-v1.0)")
else:
    st.warning("No ML scoring detected. Run `python -m src.ml.score` to populate priorities.")

# Honest data quality note — covers the AbuseIPDB quota exhaustion
st.caption(
    "📌 **Geographic enrichment** completed via MaxMind GeoLite2 (97.27% coverage of 19,040 "
    "external IPs). **Threat reputation enrichment** via AbuseIPDB was capped at the free-tier "
    "daily quota (1,000 requests), so reputation scores are unavailable on most IPs. "
    "Both enrichment caches are persisted to disk for incremental top-ups in future runs."
)

# ---------------------------------------------------------------------
# Navigation cards
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Explore the dashboard")

nav_col1, nav_col2, nav_col3, nav_col4 = st.columns(4)

with nav_col1:
    st.markdown(
        """
        <a href="Summary" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">📊</span>
                <h3>Summary</h3>
                <p>Operational KPIs, priority distribution donut, and per-family alert quality scores.</p>
            </div>
        </a>
        <a href="Timeline" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">📈</span>
                <h3>Timeline</h3>
                <p>Chronological 5-day attack progression with per-family filtering.</p>
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with nav_col2:
    st.markdown(
        """
        <a href="Geography" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🌍</span>
                <h3>Geography</h3>
                <p>World map of attacker origins with attack flow arcs to the lab network.</p>
            </div>
        </a>
        <a href="Heatmap" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🔥</span>
                <h3>Heatmap</h3>
                <p>Hour × day attack pattern revealing the 100% working-hours signature.</p>
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with nav_col3:
    st.markdown(
        """
        <a href="Alerts" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🚨</span>
                <h3>Alerts</h3>
                <p>Operational queue of top-priority events with filtering and CSV export.</p>
            </div>
        </a>
        <a href="User_Risk" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🕵️</span>
                <h3>User Risk (CERT)</h3>
                <p>Insider threat scoring across 1,000 users with ML-driven risk leaderboard.</p>
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with nav_col4:
    st.markdown(
        """
        <a href="Scenarios" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🎭</span>
                <h3>Scenarios (CERT)</h3>
                <p>Per-scenario insider threat detection — WikiLeaks, Job Hopper, Keylogger.</p>
            </div>
        </a>
        <a href="User_Drilldown" target="_self" class="nav-card-link">
            <div class="nav-card">
                <span class="nav-icon">🔬</span>
                <h3>User Drilldown (CERT)</h3>
                <p>Investigate any single user — behavioral timeline, baseline comparison.</p>
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

st.markdown(
    """
    <p style="color:#7d8a98; font-size:0.85em; text-align:center; padding-top:1rem;">
        💡 SOC Sentinel is a portfolio capstone project demonstrating end-to-end
        data warehousing, ML model fusion, and dashboard development on the CICIDS2017 dataset.
    </p>
    """,
    unsafe_allow_html=True,
)

render_sidebar_footer()