"""
User Risk Leaderboard — Phase 2 operational view.

Shows all 1,000 users ranked by ML risk score with rich filtering.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.style import (
    set_page_config,
    render_sidebar_header,
    render_sidebar_footer,
    format_compact,
    COLORS,
)
from app.data import get_phase2_kpis, get_user_risk_leaderboard


# ---------------------------------------------------------------------
# Scenario name mapping (for display)
# ---------------------------------------------------------------------

SCENARIO_NAMES = {
    0: "Legitimate",
    1: "WikiLeaks Leaker",
    2: "Job Hopper",
    3: "Sysadmin Keylogger",
}

SCENARIO_COLORS = {
    0: "#6a7a87",
    1: "#e63946",
    2: "#f4a261",
    3: "#9b5de5",
}

RISK_LABEL_COLORS = {
    "high":     "#e63946",
    "elevated": "#f4a261",
    "low":      "#e9c46a",
    "baseline": "#6a7a87",
}


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="User Risk", page_icon="🕵️")
render_sidebar_header()

# Custom CSS for KPI cards and bordered chart containers
st.markdown(
    """
    <style>
    .kpi-card {
        background: linear-gradient(145deg, #1c2128, #181c22);
        border: 1px solid #2a2f37;
        border-radius: 12px;
        padding: 1.1rem 1.4rem;
        height: 100%;
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #5a8da4;
        transform: translateY(-2px);
    }
    .kpi-card .kpi-label {
        color: #a3b1c2;
        font-size: 0.8em;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin: 0;
    }
    .kpi-card .kpi-value {
        color: #e6edf3;
        font-size: 2.1em;
        font-weight: 700;
        margin: 0.2rem 0;
        line-height: 1.1;
    }
    .kpi-card .kpi-delta {
        color: #5a8da4;
        font-size: 0.8em;
        margin: 0;
    }
    .kpi-card.critical .kpi-delta {
        color: #e63946;
    }
    .kpi-card.success .kpi-delta {
        color: #90c8a4;
    }
    .kpi-card .kpi-icon {
        font-size: 1.3em;
        margin-bottom: 0.4rem;
        opacity: 0.8;
    }
    .chart-container {
        background: rgba(28, 33, 40, 0.4);
        border: 1px solid #2a2f37;
        border-radius: 12px;
        padding: 1rem 1.25rem;
        margin: 0.5rem 0 1rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🕵️ User Risk Leaderboard")
st.markdown(
    "Phase 2 insider threat ranking. Every user scored by ML behavioral analytics "
    "trained on CERT r4.2 with personal-baseline ratios, peer-group z-scores, "
    "and multi-signal composite indicators."
)

# ---------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------

with st.spinner("Loading user risk data..."):
    kpis = get_phase2_kpis()

# ---------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------

st.sidebar.markdown("### 🔍 Filters")

risk_filter = st.sidebar.multiselect(
    "Risk labels",
    options=["high", "elevated", "low", "baseline"],
    default=["high", "elevated"],
    help="Show users with these risk classifications",
)

scenario_filter_labels = st.sidebar.multiselect(
    "Show scenarios",
    options=["Legitimate", "WikiLeaks Leaker", "Job Hopper", "Sysadmin Keylogger"],
    default=["Legitimate", "WikiLeaks Leaker", "Job Hopper", "Sysadmin Keylogger"],
    help="Filter by ground-truth scenario classification",
)
scenario_filter = [
    k for k, v in SCENARIO_NAMES.items() if v in scenario_filter_labels
]

min_score = st.sidebar.slider(
    "Minimum risk score",
    min_value=0.0,
    max_value=1.0,
    value=0.0,
    step=0.05,
    help="Filter to users with risk score above this threshold",
)

# Load filtered users
with st.spinner("Loading filtered users..."):
    users_df = get_user_risk_leaderboard(
        min_score=min_score,
        risk_filter=risk_filter if risk_filter else None,
        scenario_filter=scenario_filter if scenario_filter else None,
    )

if users_df.empty:
    st.warning("No users match the current filters.")
    st.stop()

# ---------------------------------------------------------------------
# Section 1 — KPI cards
# ---------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

# Compute values
flagged_in_view = (users_df["risk_label"].isin(["high", "elevated"])).sum()
truly_malicious_in_view = (users_df["is_malicious_truth"] == 1).sum()
flagged_correct = (
    (users_df["risk_label"].isin(["high", "elevated"]))
    & (users_df["is_malicious_truth"] == 1)
).sum()
precision_in_view = (
    f"{flagged_correct / flagged_in_view * 100:.1f}%" if flagged_in_view > 0 else "—"
)

with col1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">👥</div>
            <p class="kpi-label">Users in view</p>
            <p class="kpi-value">{format_compact(len(users_df))}</p>
            <p class="kpi-delta">of {kpis['total_users']:,} total</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    flagged_pct = flagged_in_view / max(len(users_df), 1) * 100
    st.markdown(
        f"""
        <div class="kpi-card critical">
            <div class="kpi-icon">🚩</div>
            <p class="kpi-label">Flagged (high/elevated)</p>
            <p class="kpi-value">{flagged_in_view}</p>
            <p class="kpi-delta">{flagged_pct:.1f}% of view</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-icon">⚠️</div>
            <p class="kpi-label">Malicious (truth)</p>
            <p class="kpi-value">{truly_malicious_in_view}</p>
            <p class="kpi-delta">Known insider threats</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""
        <div class="kpi-card success">
            <div class="kpi-icon">🎯</div>
            <p class="kpi-label">Precision in view</p>
            <p class="kpi-value">{precision_in_view}</p>
            <p class="kpi-delta">Of flagged users</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("---")

# ---------------------------------------------------------------------
# Section 2 — Risk score distribution histogram (bordered container)
# ---------------------------------------------------------------------

with st.container(border=True):
    st.subheader("Risk score distribution")

    malicious_scores = users_df[users_df["is_malicious_truth"] == 1]["risk_score"]
    legitimate_scores = users_df[users_df["is_malicious_truth"] == 0]["risk_score"]

    fig = go.Figure()

    fig.add_trace(go.Histogram(
        x=legitimate_scores,
        name="Legitimate",
        marker_color="#5a8da4",
        opacity=0.75,
        xbins=dict(start=0, end=1, size=0.05),
        hovertemplate="<b>Legitimate</b><br>Score: %{x:.2f}<br>Users: %{y}<extra></extra>",
    ))

    fig.add_trace(go.Histogram(
        x=malicious_scores,
        name="Malicious (truth)",
        marker_color="#e63946",
        opacity=0.85,
        xbins=dict(start=0, end=1, size=0.05),
        hovertemplate="<b>Malicious</b><br>Score: %{x:.2f}<br>Users: %{y}<extra></extra>",
    ))

    fig.add_vline(
        x=0.315,
        line_dash="dash",
        line_color="#e6edf3",
        annotation_text="Operating threshold (0.315)",
        annotation_position="top right",
        annotation_font_color="#e6edf3",
    )

    fig.update_layout(
        barmode="overlay",
        height=350,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(
            title="Risk score",
            color="#a3b1c2",
            gridcolor="#2a2f37",
            range=[0, 1],
        ),
        yaxis=dict(
            title="User count",
            color="#a3b1c2",
            gridcolor="#2a2f37",
            type="log",
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            x=0,
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3"),
        ),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "💡 Y-axis is log scale to handle the imbalance (930 legitimate vs 70 malicious). "
        "Malicious users (red) skew right; legitimate (blue) cluster near zero. "
        "Dashed line marks the operating threshold."
    )

# ---------------------------------------------------------------------
# Section 3 — Main ranked user table
# ---------------------------------------------------------------------

st.subheader("Ranked user table")

display = users_df.copy()
display["Scenario"] = display["malicious_scenario"].fillna(0).astype(int).map(SCENARIO_NAMES)
display["Status"] = display.apply(
    lambda r: "🔴 True Positive" if (r["risk_label"] in ["high", "elevated"] and r["is_malicious_truth"] == 1)
    else "⚠️ False Positive" if (r["risk_label"] in ["high", "elevated"] and r["is_malicious_truth"] == 0)
    else "❌ False Negative" if (r["risk_label"] not in ["high", "elevated"] and r["is_malicious_truth"] == 1)
    else "✓ True Negative",
    axis=1,
)
display["Employment"] = display["employment_active"].map({1: "✅ Active", 0: "🚪 Departed"})
display["risk_score"] = display["risk_score"].astype(float).round(3)

table = display[[
    "user_id", "employee_name", "role", "department",
    "Employment", "risk_score", "risk_label", "Scenario", "Status",
]].rename(columns={
    "user_id": "User ID",
    "employee_name": "Name",
    "role": "Role",
    "department": "Department",
    "risk_score": "Risk Score",
    "risk_label": "Risk Label",
})

st.dataframe(
    table,
    use_container_width=True,
    hide_index=True,
    height=460,
    column_config={
        "Risk Score": st.column_config.ProgressColumn(
            "Risk Score",
            help="ML risk probability (0-1)",
            min_value=0.0,
            max_value=1.0,
            format="%.3f",
        ),
    },
)

st.caption(
    "💡 Sort by clicking column headers. The Status column shows model verdict "
    "vs ground truth — green checks are correct, red dots are catches, "
    "warnings are false alarms, X is a miss."
)

st.markdown("---")

# ---------------------------------------------------------------------
# Section 4 — Catch vs miss breakdown
# ---------------------------------------------------------------------

st.subheader("Detection breakdown by scenario")

scenario_breakdown = users_df.copy()
scenario_breakdown["scenario_name"] = scenario_breakdown["malicious_scenario"].fillna(0).astype(int).map(SCENARIO_NAMES)
scenario_breakdown["caught"] = scenario_breakdown["risk_label"].isin(["high", "elevated"])

summary = (
    scenario_breakdown.groupby("scenario_name")
    .agg(
        total=("user_id", "count"),
        caught=("caught", "sum"),
        avg_score=("risk_score", "mean"),
        max_score=("risk_score", "max"),
    )
    .reset_index()
)
summary["catch_rate"] = (summary["caught"] / summary["total"] * 100).round(1)
summary["avg_score"] = summary["avg_score"].astype(float).round(3)
summary["max_score"] = summary["max_score"].astype(float).round(3)
summary = summary.sort_values("catch_rate", ascending=False)

col_left, col_right = st.columns([3, 2])

with col_left:
    fig = go.Figure(data=[
        go.Bar(
            y=summary["scenario_name"],
            x=summary["catch_rate"],
            orientation="h",
            marker=dict(
                color=[
                    SCENARIO_COLORS.get(
                        next((k for k, v in SCENARIO_NAMES.items() if v == name), 0), "#888"
                    )
                    for name in summary["scenario_name"]
                ],
            ),
            text=[
                f"{int(c)}/{int(t)} ({rate:.1f}%)"
                for c, t, rate in zip(summary["caught"], summary["total"], summary["catch_rate"])
            ],
            textposition="outside",
            textfont=dict(color="#e6edf3", size=11),
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Catch rate: %{x:.1f}%<extra></extra>"
            ),
        )
    ])
    fig.update_layout(
        height=320,
        margin=dict(l=10, r=120, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(
            title="Catch rate (%)",
            color="#a3b1c2",
            gridcolor="#2a2f37",
            range=[0, 105],
        ),
        yaxis=dict(
            color="#e6edf3",
            autorange="reversed",
        ),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.markdown("**Per-scenario detail**")
    display_summary = summary[[
        "scenario_name", "total", "caught", "avg_score", "max_score"
    ]].rename(columns={
        "scenario_name": "Scenario",
        "total": "Total",
        "caught": "Caught",
        "avg_score": "Avg Score",
        "max_score": "Max Score",
    })
    st.dataframe(
        display_summary, use_container_width=True, hide_index=True,
        column_config={
            "Avg Score": st.column_config.ProgressColumn(
                "Avg Score", min_value=0.0, max_value=1.0, format="%.3f"
            ),
            "Max Score": st.column_config.ProgressColumn(
                "Max Score", min_value=0.0, max_value=1.0, format="%.3f"
            ),
        },
    )

# ---------------------------------------------------------------------
# Section 5 — Insights
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Key insights")

col_a, col_b, col_c = st.columns(3)

with col_a:
    s1 = summary[summary["scenario_name"] == "WikiLeaks Leaker"]
    s1_rate = float(s1["catch_rate"].iloc[0]) if not s1.empty else 0
    st.success(
        f"**🎯 Scenario 1 — WikiLeaks Leaker**\n\n"
        f"**{s1_rate:.1f}% catch rate.** Personal-baseline USB ratio is the dominant signal "
        f"— these users normally have low USB activity, so even a modest spike registers strongly."
    )

with col_b:
    s2 = summary[summary["scenario_name"] == "Job Hopper"]
    s2_rate = float(s2["catch_rate"].iloc[0]) if not s2.empty else 0
    st.warning(
        f"**⚠️ Scenario 2 — Job Hopper**\n\n"
        f"**{s2_rate:.1f}% catch rate.** These users (Salesmen, Engineers) have naturally high "
        f"baselines — their attack signals blend with legitimate workload. The hardest scenario "
        f"for behavioral analytics alone."
    )

with col_c:
    s3 = summary[summary["scenario_name"] == "Sysadmin Keylogger"]
    s3_rate = float(s3["catch_rate"].iloc[0]) if not s3.empty else 0
    st.info(
        f"**🔬 Scenario 3 — Keylogger**\n\n"
        f"**{s3_rate:.1f}% catch rate.** Limited by only 1 post-baseline attack-day across 10 users. "
        f"Production deployment would require EDR + file integrity monitoring to address this gap."
    )

render_sidebar_footer()