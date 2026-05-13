"""
User Drilldown — investigate one user in depth.
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
)
from app.data import (
    get_user_search_options,
    get_user_profile,
    get_user_activity_timeline,
    get_user_hourly_activity,
)


SCENARIO_NAMES = {
    None: "Legitimate",
    0: "Legitimate",
    1: "📤 WikiLeaks Leaker",
    2: "💼 Job Hopper",
    3: "🔐 Sysadmin Keylogger",
}


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="User Drilldown", page_icon="🔬")
render_sidebar_header()

st.markdown(
    """
    <style>
    .profile-card {
        background: linear-gradient(145deg, #1c2128, #181c22);
        border: 1px solid #2a2f37;
        border-radius: 12px;
        padding: 1.3rem 1.5rem;
        margin-bottom: 1rem;
    }
    .profile-card h2 {
        color: #e6edf3;
        margin: 0 0 0.3rem 0;
    }
    .profile-card .subtitle {
        color: #a3b1c2;
        margin: 0 0 1rem 0;
    }
    .profile-attr {
        color: #a3b1c2;
        font-size: 0.85em;
        margin: 0.15rem 0;
    }
    .profile-attr b {
        color: #e6edf3;
    }
    .risk-badge {
        display: inline-block;
        padding: 0.4rem 1.2rem;
        border-radius: 8px;
        font-weight: 700;
        font-size: 1.5em;
        margin-top: 0.5rem;
    }
    .risk-badge.high     { background: #e63946; color: white; }
    .risk-badge.elevated { background: #f4a261; color: white; }
    .risk-badge.low      { background: #e9c46a; color: black; }
    .risk-badge.baseline { background: #6a7a87; color: white; }
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

st.title("🔬 User Drilldown")
st.markdown(
    "Forensic investigation view. Select any user to see their complete behavioral "
    "profile, ML risk assessment, and activity timeline."
)

# ---------------------------------------------------------------------
# User selector
# ---------------------------------------------------------------------

users_options = get_user_search_options()

# Build display strings: "USER_ID — Employee Name (Role · Department)"
users_options["display"] = users_options.apply(
    lambda r: f"{r['user_id']} — {r['employee_name']} ({r['role']} · {r['department']})",
    axis=1,
)
display_to_id = dict(zip(users_options["display"], users_options["user_id"]))

# Default to highest-risk user
default_display = users_options["display"].iloc[0] if not users_options.empty else None

selected_display = st.selectbox(
    "Select user to investigate",
    options=users_options["display"].tolist(),
    index=0,
    help="Search by user ID, name, role, or department",
)
selected_user_id = display_to_id.get(selected_display)

if not selected_user_id:
    st.warning("No user selected.")
    st.stop()

# ---------------------------------------------------------------------
# Load profile
# ---------------------------------------------------------------------

with st.spinner("Loading user profile..."):
    profile = get_user_profile(selected_user_id)

if profile is None:
    st.error(f"User {selected_user_id} not found.")
    st.stop()

# ---------------------------------------------------------------------
# Section 1 — Profile card
# ---------------------------------------------------------------------

scenario = profile.get("malicious_scenario") or 0
scenario_label = SCENARIO_NAMES.get(scenario, "Legitimate")
is_malicious = profile.get("is_malicious", 0) == 1
risk_score = profile.get("risk_score")
risk_label = profile.get("risk_label", "baseline")
employment = "✅ Active" if profile.get("is_current") == 1 else "🚪 Departed"

attack_start = profile.get("attack_window_start")
attack_end = profile.get("attack_window_end")
attack_window_str = (
    f"{attack_start.strftime('%Y-%m-%d')} to {attack_end.strftime('%Y-%m-%d')}"
    if attack_start and attack_end and pd.notna(attack_start) else "—"
)

col_left, col_right = st.columns([3, 2])

with col_left:
    badge_html = (
        f'<div class="risk-badge {risk_label}">'
        f'{risk_label.upper()} · {risk_score:.3f}'
        f'</div>' if risk_score is not None else
        '<div class="risk-badge baseline">UNSCORED</div>'
    )
    st.markdown(
        f"""
        <div class="profile-card">
            <h2>{profile.get('employee_name', '—')}</h2>
            <p class="subtitle"><b>{profile.get('user_id', '—')}</b> · {employment}</p>
            <p class="profile-attr"><b>Role:</b> {profile.get('role', '—')}</p>
            <p class="profile-attr"><b>Department:</b> {profile.get('department', '—')}</p>
            <p class="profile-attr"><b>Team:</b> {profile.get('team', '—') or '—'}</p>
            <p class="profile-attr"><b>Supervisor:</b> {profile.get('supervisor_name', '—') or '—'}</p>
            <p class="profile-attr"><b>Email:</b> {profile.get('email_address', '—') or '—'}</p>
            <p class="profile-attr" style="margin-top:0.6rem;"><b>Ground truth:</b> {scenario_label}</p>
            <p class="profile-attr"><b>Attack window:</b> {attack_window_str}</p>
            {badge_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_right:
    st.markdown(
        f"""
        <div class="profile-card">
            <h2 style="color: #5a8da4; font-size: 1em;">📊 Baseline behavioral profile</h2>
            <p class="profile-attr" style="font-size: 0.8em; color: #7d8a98; margin-bottom: 0.5rem;">
                First {profile.get('baseline_active_days', 0)} active days
                ({profile.get('baseline_from', '—')} → {profile.get('baseline_to', '—')})
            </p>
            <p class="profile-attr"><b>USB connects/day:</b> {profile.get('baseline_usb_per_day', 0):.2f}</p>
            <p class="profile-attr"><b>Emails sent/day:</b> {profile.get('baseline_emails_per_day', 0):.2f}</p>
            <p class="profile-attr"><b>External emails/day:</b> {profile.get('baseline_ext_emails_per_day', 0):.2f}</p>
            <p class="profile-attr"><b>File accesses/day:</b> {profile.get('baseline_files_per_day', 0):.2f}</p>
            <p class="profile-attr"><b>After-hours %:</b> {profile.get('baseline_after_hours_pct', 0)*100:.1f}%</p>
            <p class="profile-attr"><b>Weekend %:</b> {profile.get('baseline_weekend_pct', 0)*100:.1f}%</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------
# Load timeline data
# ---------------------------------------------------------------------

with st.spinner("Loading activity timeline..."):
    timeline = get_user_activity_timeline(selected_user_id)
    hourly = get_user_hourly_activity(selected_user_id)

if timeline.empty:
    st.warning("No daily feature data for this user.")
    st.stop()

# ---------------------------------------------------------------------
# Section 2 — Behavioral timeline
# ---------------------------------------------------------------------

st.markdown('<div class="chart-container">', unsafe_allow_html=True)
st.subheader("Daily behavioral timeline")
st.caption(
    "Activity counts per day with attack window highlighted (if applicable). "
    "USB and external email are the most insider-relevant indicators."
)

metric_choice = st.radio(
    "Metric to display",
    options=[
        "USB connects",
        "External emails",
        "File accesses",
        "After-hours events",
        "Total events",
    ],
    horizontal=True,
)

metric_to_col = {
    "USB connects":       ("usb_connects", "baseline_usb_per_day"),
    "External emails":    ("ext_emails", "baseline_ext_emails_per_day"),
    "File accesses":      ("file_accesses", None),
    "After-hours events": ("after_hours_events", None),
    "Total events":       ("events_total", None),
}
col_name, baseline_col = metric_to_col[metric_choice]
baseline_value = timeline[baseline_col].iloc[0] if baseline_col and baseline_col in timeline.columns else None

fig = go.Figure()

# Activity bars
fig.add_trace(go.Bar(
    x=timeline["feature_date"],
    y=timeline[col_name],
    name=metric_choice,
    marker_color="#5a8da4",
    hovertemplate=(
        "<b>%{x|%a %Y-%m-%d}</b><br>"
        f"{metric_choice}: %{{y}}<extra></extra>"
    ),
))

# Baseline reference line
if baseline_value is not None and pd.notna(baseline_value):
    fig.add_hline(
        y=float(baseline_value),
        line_dash="dash",
        line_color="#90c8a4",
        annotation_text=f"Personal baseline ({baseline_value:.1f}/day)",
        annotation_position="top right",
        annotation_font_color="#90c8a4",
    )

# Attack window shading
if pd.notna(attack_start) and pd.notna(attack_end):
    fig.add_vrect(
        x0=attack_start, x1=attack_end,
        fillcolor="rgba(230, 57, 70, 0.15)",
        line_width=0,
        annotation_text="Attack window",
        annotation_position="top left",
        annotation_font_color="#e63946",
    )

fig.update_layout(
    height=380,
    margin=dict(l=10, r=10, t=20, b=10),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e6edf3"),
    xaxis=dict(
        title="Date",
        color="#a3b1c2",
        gridcolor="#2a2f37",
    ),
    yaxis=dict(
        title=metric_choice,
        color="#a3b1c2",
        gridcolor="#2a2f37",
    ),
    showlegend=False,
)
st.plotly_chart(fig, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------
# Section 3 — Behavioral fingerprint comparison (this user vs baseline)
# ---------------------------------------------------------------------

st.markdown('<div class="chart-container">', unsafe_allow_html=True)
st.subheader("Behavioral fingerprint — peak vs baseline")
st.caption(
    "How far this user deviated from their own baseline during their post-baseline period."
)

# Get peak post-baseline values for radar
import pandas as pd

if pd.notna(profile.get("baseline_to")):
    post_baseline = timeline[timeline["feature_date"] >= pd.to_datetime(profile["baseline_to"])]
else:
    post_baseline = timeline

if not post_baseline.empty:
    peak_usb = post_baseline["usb_connects"].max()
    peak_ext = post_baseline["ext_emails"].max()
    peak_file = post_baseline["file_accesses"].max()
    peak_after = post_baseline["after_hours_events"].max()
    peak_signals = post_baseline["multi_signal_count"].max()

    baseline_usb = float(profile.get("baseline_usb_per_day") or 0)
    baseline_ext = float(profile.get("baseline_ext_emails_per_day") or 0)
    baseline_file = float(profile.get("baseline_files_per_day") or 0)
    baseline_after = float(profile.get("baseline_after_hours_pct") or 0) * 100  # approximate

    # Normalize for radar — divide each by a max-of-the-two with a floor
    def norm(peak, base):
        m = max(peak, base, 1)
        return peak / m, base / m

    p_usb, b_usb = norm(peak_usb, baseline_usb)
    p_ext, b_ext = norm(peak_ext, baseline_ext)
    p_file, b_file = norm(peak_file, baseline_file)
    p_after, b_after = norm(peak_after, baseline_after)
    p_signals = min(peak_signals / 5.0, 1.0)  # cap at 5

    labels = ["USB connects", "External emails", "File accesses",
              "After-hours events", "Multi-signal days"]
    peak_vals = [p_usb, p_ext, p_file, p_after, p_signals]
    base_vals = [b_usb, b_ext, b_file, b_after, 0]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=base_vals + [base_vals[0]],
        theta=labels + [labels[0]],
        fill="toself",
        name="Personal baseline",
        line=dict(color="#5a8da4", width=2),
        opacity=0.5,
    ))
    fig.add_trace(go.Scatterpolar(
        r=peak_vals + [peak_vals[0]],
        theta=labels + [labels[0]],
        fill="toself",
        name="Peak post-baseline day",
        line=dict(color="#e63946", width=2),
        opacity=0.5,
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(visible=True, range=[0, 1.05],
                            gridcolor="#2a2f37", color="#a3b1c2"),
            angularaxis=dict(color="#e6edf3", gridcolor="#2a2f37"),
        ),
        height=420,
        margin=dict(l=60, r=60, t=20, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        legend=dict(
            orientation="h",
            yanchor="top", y=-0.1,
            x=0.5, xanchor="center",
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3"),
        ),
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------
# Section 4 — Hour-of-day activity heatmap
# ---------------------------------------------------------------------

st.markdown('<div class="chart-container">', unsafe_allow_html=True)
st.subheader("Hour-of-day activity pattern")
st.caption(
    "Heatmap showing when this user is most active. Bright cells outside "
    "working hours (9 AM - 5 PM) or on weekends are operationally interesting."
)

if not hourly.empty:
    day_order = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    day_map = {0: "Sunday", 1: "Monday", 2: "Tuesday", 3: "Wednesday",
               4: "Thursday", 5: "Friday", 6: "Saturday"}

    activity_filter = st.selectbox(
        "Activity category",
        options=["All activities"] + sorted(hourly["activity_category"].unique().tolist()),
        index=0,
    )

    filtered = hourly.copy() if activity_filter == "All activities" else hourly[hourly["activity_category"] == activity_filter]
    aggregated = filtered.groupby(["day_of_week", "hour_24"])["events"].sum().reset_index()
    aggregated["day_name"] = aggregated["day_of_week"].map(day_map)

    matrix = aggregated.pivot_table(
        index="day_name", columns="hour_24", values="events", fill_value=0
    ).reindex(index=day_order, columns=list(range(24)), fill_value=0)

    fig = go.Figure(data=go.Heatmap(
        z=matrix.values,
        x=[f"{h:02d}:00" for h in range(24)],
        y=day_order,
        colorscale=[
            [0.0, "#1c2128"],
            [0.1, "#2d3a4d"],
            [0.3, "#4a6c8a"],
            [0.5, "#e9c46a"],
            [0.8, "#f4a261"],
            [1.0, "#e63946"],
        ],
        hovertemplate="<b>%{y}, %{x}</b><br>Events: %{z}<extra></extra>",
        colorbar=dict(
            title=dict(text="Events", font=dict(color="#e6edf3")),
            tickfont=dict(color="#e6edf3"),
        ),
        xgap=2, ygap=2,
    ))

    fig.add_shape(
        type="rect",
        x0=8.5, x1=16.5,
        y0=-0.5, y1=6.5,
        line=dict(color="rgba(255,255,255,0.3)", width=2, dash="dash"),
        fillcolor="rgba(0,0,0,0)",
        layer="above",
    )

    fig.update_layout(
        height=380,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(
            title="Hour of day",
            color="#a3b1c2",
            showgrid=False,
            dtick=2,
        ),
        yaxis=dict(
            color="#e6edf3",
            autorange="reversed",
            showgrid=False,
        ),
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------
# Section 5 — Raw daily feature table
# ---------------------------------------------------------------------

st.subheader("Daily activity log")

show_attack_only = st.checkbox("Show only attack-window days", value=False)

table = timeline.copy()
if show_attack_only:
    table = table[table["in_attack_window"] == 1]

if not table.empty:
    table_display = table[[
        "feature_date", "events_total", "usb_connects", "emails_sent",
        "ext_emails", "file_accesses", "logons", "after_hours_events",
        "usb_zscore_peer", "multi_signal_count", "in_attack_window",
    ]].copy()
    table_display["feature_date"] = table_display["feature_date"].dt.strftime("%Y-%m-%d")
    table_display["in_attack_window"] = table_display["in_attack_window"].map({1: "🔴", 0: ""})
    table_display = table_display.rename(columns={
        "feature_date": "Date",
        "events_total": "Total",
        "usb_connects": "USB",
        "emails_sent": "Emails",
        "ext_emails": "Ext Emails",
        "file_accesses": "Files",
        "logons": "Logons",
        "after_hours_events": "After Hours",
        "usb_zscore_peer": "USB Z",
        "multi_signal_count": "Signals",
        "in_attack_window": "Attack?",
    })
    st.dataframe(table_display, use_container_width=True, hide_index=True, height=380)
else:
    st.info("No matching days.")

render_sidebar_footer()