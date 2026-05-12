"""
Heatmap page — hour-of-day × day-of-week attack pattern visualization.
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
    ATTACK_FAMILY_COLORS,
)
from app.data import get_hourly_heatmap, get_working_hours_summary


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Heatmap", page_icon="🔥")
render_sidebar_header()

st.title("🔥 Temporal Attack Patterns")
st.markdown(
    "Hour-of-day × day-of-week heatmap of attack volume. Each cell represents "
    "the number of attack events that occurred during that specific hour-day combination."
)

# ---------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------

with st.spinner("Loading heatmap data..."):
    heatmap_df = get_hourly_heatmap()
    wh_summary = get_working_hours_summary()

if heatmap_df.empty:
    st.warning("No attack events found.")
    st.stop()

# ---------------------------------------------------------------------
# Section 1 — Filter controls
# ---------------------------------------------------------------------

available_families = sorted(heatmap_df["attack_family"].unique())

col_filter1, col_filter2 = st.columns([2, 1])

with col_filter1:
    selected_family = st.selectbox(
        "Attack family",
        options=["All families"] + available_families,
        index=0,
        help="Filter the heatmap to a specific attack type",
    )

with col_filter2:
    color_scale = st.selectbox(
        "Color scale",
        options=["Linear", "Logarithmic"],
        index=1,
        help="Logarithmic better reveals patterns when one family dominates",
    )

# Filter data
if selected_family == "All families":
    filtered = heatmap_df.copy()
else:
    filtered = heatmap_df[heatmap_df["attack_family"] == selected_family].copy()

# Aggregate to hour × day grid
grid = (
    filtered.groupby(["day_name", "hour_24"])["event_count"]
    .sum()
    .reset_index()
)

# ---------------------------------------------------------------------
# Section 2 — Main heatmap
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader(f"Attack distribution — {selected_family}")

# Build a full hour×day matrix (0-23 hours × 5 days), filling missing cells with 0
day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
hour_range = list(range(0, 24))

# Pivot to wide form
matrix = grid.pivot_table(
    index="day_name",
    columns="hour_24",
    values="event_count",
    fill_value=0,
)

# Reindex to ensure all days/hours are present
matrix = matrix.reindex(index=day_order, columns=hour_range, fill_value=0)

# Apply log transform if requested (add 1 to avoid log(0))
import numpy as np
if color_scale == "Logarithmic":
    display_matrix = np.log10(matrix.values + 1)
    color_label = "log₁₀(events + 1)"
else:
    display_matrix = matrix.values
    color_label = "Events"

# Build hover text with raw counts (not log)
hover_text = []
for i, day in enumerate(day_order):
    row = []
    for h in hour_range:
        raw = int(matrix.loc[day, h])
        # Format hour: 0 → "12 AM", 13 → "1 PM"
        if h == 0:
            hour_label = "12 AM"
        elif h < 12:
            hour_label = f"{h} AM"
        elif h == 12:
            hour_label = "12 PM"
        else:
            hour_label = f"{h - 12} PM"
        row.append(
            f"<b>{day}, {hour_label}</b><br>"
            f"{raw:,} events"
        )
    hover_text.append(row)

# Plot
fig = go.Figure(data=go.Heatmap(
    z=display_matrix,
    x=[f"{h:02d}:00" for h in hour_range],
    y=day_order,
    colorscale=[
        [0.0, "#1c2128"],
        [0.1, "#2d3a4d"],
        [0.3, "#4a6c8a"],
        [0.5, "#e9c46a"],
        [0.8, "#f4a261"],
        [1.0, "#e63946"],
    ],
    text=hover_text,
    hovertemplate="%{text}<extra></extra>",
    colorbar=dict(
        title=dict(text=color_label, font=dict(color="#e6edf3")),
        tickfont=dict(color="#e6edf3"),
        len=0.8,
        thickness=15,
    ),
    xgap=2,
    ygap=2,
))

# Highlight working hours boundary with a rectangle annotation
fig.add_shape(
    type="rect",
    x0=8.5, x1=16.5,
    y0=-0.5, y1=4.5,
    line=dict(color="rgba(255, 255, 255, 0.3)", width=2, dash="dash"),
    fillcolor="rgba(0, 0, 0, 0)",
    layer="above",
)

fig.update_layout(
    height=420,
    margin=dict(l=10, r=10, t=30, b=10),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e6edf3"),
    xaxis=dict(
        title="Hour of day",
        color="#a3b1c2",
        side="bottom",
        showgrid=False,
        tickmode="linear",
        dtick=2,
    ),
    yaxis=dict(
        title="",
        color="#e6edf3",
        autorange="reversed",
        showgrid=False,
    ),
)

st.plotly_chart(fig, use_container_width=True)

st.caption(
    "💡 Dashed white rectangle marks working hours (9 AM – 5 PM). "
    "Hover any cell for exact event counts."
)

# ---------------------------------------------------------------------
# Section 3 — Working hours analysis
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Working hours vs after hours")
st.caption(
    "How attack volume distributes between business hours (9 AM - 5 PM) "
    "and the rest of the day. In CICIDS2017's lab simulation, attacks were "
    "scripted during working hours."
)

if not wh_summary.empty:
    # Pivot
    wh_pivot = wh_summary.pivot_table(
        index="attack_family",
        columns="time_period",
        values="events",
        fill_value=0,
    ).reset_index()

    if "Working hours (9 AM - 5 PM)" not in wh_pivot.columns:
        wh_pivot["Working hours (9 AM - 5 PM)"] = 0
    if "After hours" not in wh_pivot.columns:
        wh_pivot["After hours"] = 0

    wh_pivot["Total"] = wh_pivot["Working hours (9 AM - 5 PM)"] + wh_pivot["After hours"]
    wh_pivot["Working %"] = (
        wh_pivot["Working hours (9 AM - 5 PM)"] / wh_pivot["Total"].clip(lower=1) * 100
    ).round(1)

    wh_pivot = wh_pivot.sort_values("Total", ascending=False)

    # KPI row
    col_kpi1, col_kpi2, col_kpi3 = st.columns(3)

    total_working = int(wh_summary[wh_summary["time_period"] == "Working hours (9 AM - 5 PM)"]["events"].sum())
    total_after   = int(wh_summary[wh_summary["time_period"] == "After hours"]["events"].sum())
    grand_total = max(total_working + total_after, 1)

    with col_kpi1:
        st.metric(
            "Attacks during working hours",
            format_compact(total_working),
            delta=f"{total_working/grand_total*100:.1f}% of all attacks",
            delta_color="off",
        )

    with col_kpi2:
        st.metric(
            "Attacks after hours",
            format_compact(total_after),
            delta=f"{total_after/grand_total*100:.1f}% of all attacks",
            delta_color="off",
        )

    with col_kpi3:
        ratio = total_working / max(total_after, 1)
        st.metric(
            "Working/after-hours ratio",
            f"{ratio:.1f}×",
            help="Higher = more concentrated in working hours",
        )

    # Stacked bar chart of working vs after-hours per family
    st.markdown("**Attack volume by family and time period**")

    fig_bar = go.Figure()

    fig_bar.add_trace(
        go.Bar(
            y=wh_pivot["attack_family"],
            x=wh_pivot["Working hours (9 AM - 5 PM)"],
            name="Working hours (9 AM - 5 PM)",
            orientation="h",
            marker_color="#e63946",
            hovertemplate="<b>%{y}</b><br>Working: %{x:,}<extra></extra>",
        )
    )
    fig_bar.add_trace(
        go.Bar(
            y=wh_pivot["attack_family"],
            x=wh_pivot["After hours"],
            name="After hours",
            orientation="h",
            marker_color="#5a8da4",
            hovertemplate="<b>%{y}</b><br>After: %{x:,}<extra></extra>",
        )
    )

    fig_bar.update_layout(
        barmode="stack",
        height=400,
        margin=dict(l=10, r=10, t=10, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(
            title="Events",
            type="log",
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
    st.plotly_chart(fig_bar, use_container_width=True)

    # Table view
    st.markdown("**Per-family working hours breakdown**")

    display = wh_pivot[[
        "attack_family",
        "Working hours (9 AM - 5 PM)",
        "After hours",
        "Total",
        "Working %",
    ]].rename(columns={"attack_family": "Attack Family"})

    for col in ["Working hours (9 AM - 5 PM)", "After hours", "Total"]:
        display[col] = display[col].apply(lambda x: f"{int(x):,}")
    display["Working %"] = display["Working %"].apply(lambda x: f"{x:.1f}%")

    st.dataframe(display, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------
# Section 4 — Key insights
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Key patterns")

col_insight1, col_insight2, col_insight3 = st.columns(3)

with col_insight1:
    st.info(
        "**🌅 Peak attack hours**\n\n"
        "Most attacks concentrate between **10 AM – 4 PM** — peak working hours "
        "when the scripted attack simulation was running."
    )

with col_insight2:
    st.warning(
        "**🌙 After-hours signatures**\n\n"
        "Some flows continue overnight (especially long-running connections like "
        "Heartbleed exfiltration). After-hours flows warrant scrutiny in production "
        "because legitimate user traffic should drop dramatically."
    )

with col_insight3:
    st.success(
        "**📊 Phase 2 preview**\n\n"
        "CERT insider threat (Phase 2) will use this same heatmap pattern to detect "
        "after-hours USB usage — known to be 4.7× more common at 3 AM than during "
        "business hours."
    )

render_sidebar_footer()