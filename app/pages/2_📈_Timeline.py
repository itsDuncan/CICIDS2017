"""
Timeline page — chronological attack volume across the 5-day capture window.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from app.style import (
    set_page_config,
    render_sidebar_header,
    render_sidebar_footer,
    format_compact,
    ATTACK_FAMILY_COLORS,
)
from app.data import get_attack_timeline_hourly


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Timeline", page_icon="📈")
render_sidebar_header()

st.title("📈 Attack Timeline")
st.markdown(
    "Hour-by-hour view of attack activity during the 5-day CICIDS2017 capture window "
    "(July 3-7, 2017). Each day featured different attack scenarios."
)

# ---------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------

with st.spinner("Loading hourly attack timeline..."):
    timeline_df = get_attack_timeline_hourly()

if timeline_df.empty:
    st.warning("No attack events found.")
    st.stop()

# ---------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------

available_families = sorted(timeline_df["family"].unique())

col_filter1, col_filter2 = st.columns([2, 1])

with col_filter1:
    selected_families = st.multiselect(
        "Attack families to display",
        options=available_families,
        default=available_families,
        help="Filter the timeline to specific attack families",
    )

with col_filter2:
    chart_type = st.radio(
        "Chart style",
        options=["Stacked area", "Lines"],
        horizontal=True,
        help="Stacked area shows cumulative volume; lines show per-family curves",
    )

# Filter
filtered_df = timeline_df[timeline_df["family"].isin(selected_families)].copy()

if filtered_df.empty:
    st.warning("No data for selected filters.")
    st.stop()

# ---------------------------------------------------------------------
# Section 1 — Main timeline chart
# ---------------------------------------------------------------------

st.subheader("Hourly attack volume")

# Pivot for plotting
pivot_df = filtered_df.pivot_table(
    index="hour_bucket",
    columns="family",
    values="events",
    fill_value=0,
).reset_index()

fig = go.Figure()

# Plot in a specific order (rarer attacks on top so they're visible)
plot_order = ["DDoS", "DoS", "Reconnaissance", "Brute Force",
              "Web Attack", "Botnet", "Infiltration", "Exploit"]
plot_order = [f for f in plot_order if f in pivot_df.columns]

for family in plot_order:
    color = ATTACK_FAMILY_COLORS.get(family, "#888")
    if chart_type == "Stacked area":
        fig.add_trace(
            go.Scatter(
                x=pivot_df["hour_bucket"],
                y=pivot_df[family],
                name=family,
                mode="lines",
                stackgroup="one",
                line=dict(width=0.5, color=color),
                fillcolor=color,
                opacity=0.85,
                hovertemplate=(
                    f"<b>{family}</b><br>"
                    "%{x|%a %H:%M}<br>"
                    "%{y:,} events<extra></extra>"
                ),
            )
        )
    else:
        fig.add_trace(
            go.Scatter(
                x=pivot_df["hour_bucket"],
                y=pivot_df[family],
                name=family,
                mode="lines+markers",
                line=dict(width=2.5, color=color),
                marker=dict(size=5),
                hovertemplate=(
                    f"<b>{family}</b><br>"
                    "%{x|%a %H:%M}<br>"
                    "%{y:,} events<extra></extra>"
                ),
            )
        )

# Highlight working hours background
for date_str in ["2017-07-03", "2017-07-04", "2017-07-05", "2017-07-06", "2017-07-07"]:
    fig.add_vrect(
        x0=f"{date_str} 09:00:00",
        x1=f"{date_str} 17:00:00",
        fillcolor="rgba(90, 141, 164, 0.06)",
        layer="below",
        line_width=0,
    )

fig.update_layout(
    height=520,
    margin=dict(l=10, r=10, t=10, b=10),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e6edf3"),
    xaxis=dict(
        title="Time",
        gridcolor="#2a2f37",
        color="#a3b1c2",
        tickformat="%a %H:%M",
    ),
    yaxis=dict(
        title="Events per hour",
        gridcolor="#2a2f37",
        color="#a3b1c2",
    ),
    hovermode="x unified",
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
    "💡 Shaded regions represent working hours (9 AM – 5 PM). "
    "Many attacks (especially DDoS) cluster around end-of-business-day, "
    "consistent with attackers exploiting reduced staffing periods."
)

# ---------------------------------------------------------------------
# Section 2 — Per-day attack signature breakdown
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Per-day attack signatures")
st.caption("Each day of the CICIDS2017 capture featured a different attack scenario.")

# Aggregate per-day
filtered_df["day"] = pd.to_datetime(filtered_df["hour_bucket"]).dt.date
daily = filtered_df.groupby(["day", "family"])["events"].sum().reset_index()
day_totals = filtered_df.groupby("day")["events"].sum().reset_index().rename(columns={"events": "total"})

# Known attack scenarios per day (from CICIDS2017 documentation)
day_descriptions = {
    pd.to_datetime("2017-07-03").date(): {
        "label": "Monday",
        "scenario": "Benign baseline (no attacks)",
        "color": COLORS["benign"] if "COLORS" in dir() else "#6a7a87",
    },
    pd.to_datetime("2017-07-04").date(): {
        "label": "Tuesday",
        "scenario": "Brute Force attacks (FTP, SSH)",
    },
    pd.to_datetime("2017-07-05").date(): {
        "label": "Wednesday",
        "scenario": "DoS variants + Heartbleed",
    },
    pd.to_datetime("2017-07-06").date(): {
        "label": "Thursday",
        "scenario": "Web Attacks + Infiltration",
    },
    pd.to_datetime("2017-07-07").date(): {
        "label": "Friday",
        "scenario": "Botnet, PortScan, DDoS",
    },
}

# Build cards
day_cols = st.columns(5)
for idx, day in enumerate(sorted(day_descriptions.keys())):
    info = day_descriptions[day]
    day_data = daily[daily["day"] == day]
    total = int(day_totals[day_totals["day"] == day]["total"].sum()) if not day_totals.empty else 0
    top_family = (
        day_data.nlargest(1, "events").iloc[0]["family"]
        if not day_data.empty else "—"
    )
    with day_cols[idx]:
        st.metric(
            label=f"{info['label']}",
            value=format_compact(total) if total > 0 else "—",
            delta=info["scenario"],
            delta_color="off",
        )
        if total > 0:
            st.caption(f"Top family: **{top_family}**")

# ---------------------------------------------------------------------
# Section 3 — Detailed daily breakdown table
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Daily breakdown table")

# Pivot for readability
pivot_table = daily.pivot_table(
    index="day",
    columns="family",
    values="events",
    fill_value=0,
).reset_index()

pivot_table["day"] = pivot_table["day"].astype(str)

# Format numeric columns
for col in pivot_table.columns:
    if col != "day":
        pivot_table[col] = pivot_table[col].apply(lambda x: f"{int(x):,}" if x > 0 else "—")

pivot_table = pivot_table.rename(columns={"day": "Date"})
st.dataframe(pivot_table, use_container_width=True, hide_index=True)

# Need COLORS import — add this if not at top
from app.style import COLORS

render_sidebar_footer()