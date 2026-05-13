"""
Scenarios page — per-scenario insider threat detection breakdown.
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
)
from app.data import (
    get_scenario_summary,
    get_scenario_behavioral_profile,
    get_malicious_users_detail,
)


# ---------------------------------------------------------------------
# Scenario metadata
# ---------------------------------------------------------------------

SCENARIO_META = {
    1: {
        "name": "WikiLeaks Leaker",
        "color": "#e63946",
        "icon": "📤",
        "users": 30,
        "tactic": "Sensitive file exfiltration via external channels",
        "description": (
            "Disgruntled employees who upload sensitive files to external sites "
            "(WikiLeaks, DropSend, etc.) before or instead of resigning."
        ),
        "duration": "~5 days",
        "key_indicators": [
            "Personal-baseline USB ratio spike (8x normal)",
            "After-hours work elevation (14% above baseline)",
            "External file uploads via HTTP (not loaded in this phase)",
        ],
        "ml_strategy": "Personal-baseline USB ratio dominates feature importance",
    },
    2: {
        "name": "Job Hopper",
        "color": "#f4a261",
        "icon": "💼",
        "users": 30,
        "tactic": "IP theft before resignation",
        "description": (
            "Users searching for jobs on company time and exfiltrating intellectual "
            "property via USB drives in their final weeks before resigning."
        ),
        "duration": "~55 days",
        "key_indicators": [
            "Sustained elevated USB activity over weeks",
            "External email to recruiters and personal accounts",
            "Peer-group USB z-score elevation",
        ],
        "ml_strategy": "Peer-group z-scores partially compensate for high natural baselines",
    },
    3: {
        "name": "Sysadmin Keylogger",
        "color": "#9b5de5",
        "icon": "🔐",
        "users": 10,
        "tactic": "Lateral movement via credential capture",
        "description": (
            "IT administrators installing keyloggers on peer machines to capture "
            "credentials and access systems outside their authorization scope."
        ),
        "duration": "~1 day",
        "key_indicators": [
            "Logons to unusual PCs (not their own)",
            "USB device usage on peer machines",
            "Single-day burst activity with no extended pattern",
        ],
        "ml_strategy": "Extreme z-scores on attack day; structurally hard with so few examples",
    },
}


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Scenarios", page_icon="🎭")
render_sidebar_header()

st.markdown(
    """
    <style>
    .scenario-card {
        background: linear-gradient(145deg, #1c2128, #181c22);
        border: 1px solid #2a2f37;
        border-left: 4px solid var(--accent);
        border-radius: 12px;
        padding: 1.25rem 1.4rem;
        height: 100%;
    }
    .scenario-card h3 {
        margin: 0 0 0.3rem 0;
        color: #e6edf3;
        font-size: 1.2em;
    }
    .scenario-card .tactic {
        color: var(--accent);
        font-weight: 600;
        margin: 0 0 0.6rem 0;
        font-size: 0.95em;
    }
    .scenario-card .description {
        color: #a3b1c2;
        font-size: 0.9em;
        line-height: 1.5;
        margin: 0 0 0.8rem 0;
    }
    .scenario-card .stat {
        color: #e6edf3;
        font-size: 0.85em;
        margin: 0.2rem 0;
    }
    .scenario-card .stat-label {
        color: #7d8a98;
        font-size: 0.75em;
        text-transform: uppercase;
        letter-spacing: 0.04em;
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

st.title("🎭 Insider Threat Scenarios")
st.markdown(
    "CERT r4.2 models three distinct insider threat scenarios. Each has different "
    "behavioral fingerprints, different attack durations, and different detection "
    "challenges. This page breaks down how the Phase 2 ML model performs against each."
)

# ---------------------------------------------------------------------
# Section 1 — Three scenario cards side by side
# ---------------------------------------------------------------------

st.markdown("### Scenario overview")

scenario_summary = get_scenario_summary()

col1, col2, col3 = st.columns(3)
for i, (col, scen_id) in enumerate(zip([col1, col2, col3], [1, 2, 3])):
    meta = SCENARIO_META[scen_id]
    s = scenario_summary[scenario_summary["scenario"] == scen_id]
    caught = int(s["flagged"].iloc[0]) if not s.empty else 0
    total = int(s["users"].iloc[0]) if not s.empty else meta["users"]
    catch_rate = caught / max(total, 1) * 100

    indicators_html = "".join([f"<li>{ind}</li>" for ind in meta["key_indicators"]])

    with col:
        st.markdown(
            f"""
            <div class="scenario-card" style="--accent: {meta['color']};">
                <h3>{meta['icon']} Scenario {scen_id}: {meta['name']}</h3>
                <p class="tactic">{meta['tactic']}</p>
                <p class="description">{meta['description']}</p>
                <p class="stat-label">Users</p>
                <p class="stat">{total} malicious users</p>
                <p class="stat-label">Avg attack window</p>
                <p class="stat">{meta['duration']}</p>
                <p class="stat-label">ML catch rate</p>
                <p class="stat"><b style="color: {meta['color']}; font-size: 1.3em;">{catch_rate:.1f}%</b> ({caught}/{total})</p>
                <p class="stat-label" style="margin-top: 0.8rem;">Key indicators</p>
                <ul style="color: #a3b1c2; font-size: 0.85em; margin: 0.2rem 0 0.6rem 0; padding-left: 1.2rem;">
                    {indicators_html}
                </ul>
                <p class="stat-label">ML strategy</p>
                <p class="stat" style="font-style: italic;">{meta['ml_strategy']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("---")

# ---------------------------------------------------------------------
# Section 2 — Detection performance comparison
# ---------------------------------------------------------------------

with st.container(border=True):
    st.subheader("Detection performance comparison")

    scen_chart = scenario_summary[scenario_summary["scenario"] != 0].copy()
    scen_chart["scenario_name"] = scen_chart["scenario"].map(
        {1: "WikiLeaks Leaker", 2: "Job Hopper", 3: "Sysadmin Keylogger"}
    )
    scen_chart["catch_rate"] = (scen_chart["flagged"] / scen_chart["users"] * 100).round(1)
    scen_chart["missed"] = scen_chart["users"] - scen_chart["flagged"]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=scen_chart["scenario_name"],
        x=scen_chart["flagged"],
        name="Caught",
        orientation="h",
        marker_color="#90c8a4",
        text=scen_chart["flagged"],
        textposition="inside",
        textfont=dict(color="white", size=12),
        hovertemplate="<b>%{y}</b><br>Caught: %{x}<extra></extra>",
    ))
    fig.add_trace(go.Bar(
        y=scen_chart["scenario_name"],
        x=scen_chart["missed"],
        name="Missed",
        orientation="h",
        marker_color="#e63946",
        text=scen_chart["missed"],
        textposition="inside",
        textfont=dict(color="white", size=12),
        hovertemplate="<b>%{y}</b><br>Missed: %{x}<extra></extra>",
    ))

    for i, row in scen_chart.iterrows():
        fig.add_annotation(
            x=row["users"] + 1,
            y=row["scenario_name"],
            text=f"<b>{row['catch_rate']:.0f}%</b>",
            showarrow=False,
            font=dict(color="#e6edf3", size=13),
            xanchor="left",
        )

    fig.update_layout(
        barmode="stack",
        height=280,
        margin=dict(l=10, r=70, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(
            title="Users (caught + missed)",
            color="#a3b1c2",
            gridcolor="#2a2f37",
        ),
        yaxis=dict(
            color="#e6edf3",
            autorange="reversed",
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

# ---------------------------------------------------------------------
# Section 3 — Behavioral fingerprint radar chart
# ---------------------------------------------------------------------

with st.container(border=True):
    st.subheader("Behavioral fingerprint by scenario")
    st.caption(
        "Normalized post-baseline behavior. Each scenario shows a distinct pattern."
    )

    profile_df = get_scenario_behavioral_profile()
    profile_df = profile_df[profile_df["scenario"].isin([0, 1, 2, 3])]
    profile_df["scenario_name"] = profile_df["scenario"].map(
        {0: "Legitimate", 1: "WikiLeaks Leaker", 2: "Job Hopper", 3: "Keylogger"}
    )

    metrics = {
        "Avg daily USB":          "avg_daily_usb",
        "Avg daily ext emails":   "avg_daily_ext_emails",
        "Avg daily files":        "avg_daily_files",
        "Avg after-hours %":      "avg_after_hours_pct",
        "Peak USB z-score":       "avg_peak_usb_z",
        "Peak USB ratio":         "avg_peak_usb_ratio",
        "Peak signals/day":       "avg_peak_signals",
    }

    normalized = profile_df.copy()
    for label, col in metrics.items():
        if col in normalized.columns:
            max_val = normalized[col].max()
            normalized[col] = normalized[col] / max(max_val, 1e-9)

    color_map = {
        "Legitimate":         "#5a8da4",
        "WikiLeaks Leaker":   "#e63946",
        "Job Hopper":         "#f4a261",
        "Keylogger":          "#9b5de5",
    }

    fig = go.Figure()
    for _, row in normalized.iterrows():
        name = row["scenario_name"]
        values = [row[col] for col in metrics.values()]
        values_loop = values + [values[0]]
        labels_loop = list(metrics.keys()) + [list(metrics.keys())[0]]
        fig.add_trace(go.Scatterpolar(
            r=values_loop,
            theta=labels_loop,
            fill="toself",
            name=name,
            line=dict(color=color_map.get(name, "#888"), width=2),
            opacity=0.5,
        ))

    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(
                visible=True,
                range=[0, 1],
                gridcolor="#2a2f37",
                color="#a3b1c2",
            ),
            angularaxis=dict(
                color="#e6edf3",
                gridcolor="#2a2f37",
            ),
        ),
        height=500,
        margin=dict(l=80, r=80, t=20, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.05,
            x=0.5,
            xanchor="center",
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3"),
        ),
        showlegend=True,
    )
    st.plotly_chart(fig, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------
# Section 4 — Caught vs missed table
# ---------------------------------------------------------------------

st.subheader("All malicious users — caught vs missed")

malicious_df = get_malicious_users_detail()

scenario_filter = st.selectbox(
    "Filter by scenario",
    options=["All scenarios", "Scenario 1 — WikiLeaks", "Scenario 2 — Job Hopper", "Scenario 3 — Keylogger"],
    index=0,
)

if scenario_filter != "All scenarios":
    scen_id = int(scenario_filter.split(" ")[1])
    malicious_df = malicious_df[malicious_df["malicious_scenario"] == scen_id]

display = malicious_df.copy()
display["Scenario"] = display["malicious_scenario"].map(
    {1: "📤 WikiLeaks", 2: "💼 Job Hopper", 3: "🔐 Keylogger"}
)
display["Status"] = display["caught"].map({1: "✅ Caught", 0: "❌ Missed"})
display["Employment"] = display["employment_active"].map({1: "Active", 0: "Departed"})
display["attack_window_start"] = pd.to_datetime(display["attack_window_start"]).dt.strftime("%Y-%m-%d")
display["attack_window_end"] = pd.to_datetime(display["attack_window_end"]).dt.strftime("%Y-%m-%d")

table = display[[
    "user_id", "employee_name", "role", "Scenario",
    "attack_window_start", "attack_window_end", "window_days",
    "risk_score", "Status", "Employment",
]].rename(columns={
    "user_id": "User ID",
    "employee_name": "Name",
    "role": "Role",
    "attack_window_start": "Attack Start",
    "attack_window_end": "Attack End",
    "window_days": "Window Days",
    "risk_score": "Risk Score",
})

st.dataframe(
    table,
    use_container_width=True,
    hide_index=True,
    height=420,
    column_config={
        "Risk Score": st.column_config.ProgressColumn(
            "Risk Score",
            min_value=0.0,
            max_value=1.0,
            format="%.3f",
        ),
    },
)

st.caption(
    f"💡 Showing {len(display)} malicious users. "
    f"{int(display['caught'].sum())} caught, {int((display['caught'] == 0).sum())} missed."
)

render_sidebar_footer()