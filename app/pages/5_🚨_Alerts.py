"""
Alerts page — operational queue of top-priority security events.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from app.style import (
    set_page_config,
    render_sidebar_header,
    render_sidebar_footer,
    format_compact,
    SEVERITY_BADGE_HTML,
    COLORS,
)
from app.data import get_top_alerts, get_alert_filter_options


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Alerts", page_icon="🚨")
render_sidebar_header()

st.title("🚨 Alert Queue")
st.markdown(
    "Top-priority security events ranked by ML fusion score. Use filters in the sidebar "
    "to narrow the queue. Click column headers to sort."
)

# ---------------------------------------------------------------------
# Load filter options
# ---------------------------------------------------------------------

with st.spinner("Loading filter options..."):
    filter_opts = get_alert_filter_options()

# ---------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------

st.sidebar.markdown("### 🔍 Filters")

priority_filter = st.sidebar.multiselect(
    "Priority levels",
    options=["critical", "high", "medium", "low", "info"],
    default=["critical", "high"],
    help="Show only events with these priority labels",
)

family_filter = st.sidebar.multiselect(
    "Attack families",
    options=filter_opts["families"],
    default=[],
    help="Empty = all families",
)

# Country filter — render with friendly names
country_options = [(iso, name) for iso, name in filter_opts["countries"].items()]
country_options.sort(key=lambda x: x[1])
country_labels = [f"{iso} — {name}" for iso, name in country_options]
country_iso_map = {f"{iso} — {name}": iso for iso, name in country_options}

selected_country_labels = st.sidebar.multiselect(
    "Source countries",
    options=country_labels,
    default=[],
    help="Filter by source IP country (empty = all)",
)
country_filter = [country_iso_map[lbl] for lbl in selected_country_labels]

min_priority = st.sidebar.slider(
    "Minimum priority score",
    min_value=0.0,
    max_value=1.0,
    value=0.0,
    step=0.05,
    help="Show only events with priority_score above this threshold",
)

result_limit = st.sidebar.select_slider(
    "Result limit",
    options=[25, 50, 100, 200, 500, 1000],
    value=100,
    help="Number of alerts to fetch",
)

# ---------------------------------------------------------------------
# Load filtered alerts
# ---------------------------------------------------------------------

with st.spinner("Loading filtered alerts..."):
    alerts = get_top_alerts(
        limit=result_limit,
        priority_filter=priority_filter if priority_filter else None,
        family_filter=family_filter if family_filter else None,
        src_country_filter=country_filter if country_filter else None,
        min_priority=min_priority,
    )

if alerts.empty:
    st.warning("No alerts match the current filters. Try loosening them.")
    st.stop()

# ---------------------------------------------------------------------
# Section 1 — Filter summary KPIs
# ---------------------------------------------------------------------

col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)

with col_kpi1:
    st.metric(
        "Alerts shown",
        format_compact(len(alerts)),
        delta=f"of {result_limit} requested",
        delta_color="off",
    )

with col_kpi2:
    critical_count = (alerts["priority_label"] == "critical").sum()
    st.metric(
        "Critical",
        format_compact(critical_count),
        delta=f"{100*critical_count/max(len(alerts),1):.1f}%",
        delta_color="off",
    )

with col_kpi3:
    avg_priority = alerts["priority_score"].astype(float).mean()
    st.metric(
        "Avg priority score",
        f"{avg_priority:.3f}",
    )

with col_kpi4:
    unique_sources = alerts["src_ip"].nunique()
    st.metric(
        "Unique sources",
        unique_sources,
        help="Distinct source IPs in the filtered view",
    )

# ---------------------------------------------------------------------
# Section 2 — Main alert table
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Alert queue")

# Pretty-format the table for display
display = alerts.copy()
display["event_time"] = pd.to_datetime(display["event_time"]).dt.strftime("%a %m-%d %H:%M:%S")
display["src_display"] = display.apply(
    lambda r: f"{r['src_ip']} ({r['src_country'] or '—'})" if not r['src_internal'] else r['src_ip'],
    axis=1,
)
display["dest_display"] = display.apply(
    lambda r: f"{r['dest_ip']} ({r['dest_country'] or '—'})" if not r['dest_internal'] else r['dest_ip'],
    axis=1,
)
display["priority_score"] = display["priority_score"].astype(float).round(3)
display["anomaly_score"] = display["anomaly_score"].astype(float).round(3)

# Final column selection
table = display[[
    "event_time",
    "priority_label",
    "priority_score",
    "attack_family",
    "src_display",
    "dest_display",
    "anomaly_score",
    "flow_duration",
    "total_fwd_packets",
]].rename(columns={
    "event_time": "Time",
    "priority_label": "Priority",
    "priority_score": "Score",
    "attack_family": "Family",
    "src_display": "Source",
    "dest_display": "Destination",
    "anomaly_score": "Anomaly",
    "flow_duration": "Duration (µs)",
    "total_fwd_packets": "Fwd Pkts",
})

# Use st.dataframe with column config for sortability and color
st.dataframe(
    table,
    use_container_width=True,
    hide_index=True,
    height=420,
    column_config={
        "Score": st.column_config.ProgressColumn(
            "Score",
            help="ML fusion priority score (0-1)",
            min_value=0.0,
            max_value=1.0,
            format="%.3f",
        ),
        "Anomaly": st.column_config.ProgressColumn(
            "Anomaly",
            help="Isolation Forest anomaly score",
            min_value=0.0,
            max_value=1.0,
            format="%.3f",
        ),
        "Duration (µs)": st.column_config.NumberColumn(
            "Duration (µs)",
            format="%d",
        ),
    },
)

# ---------------------------------------------------------------------
# Section 3 — Source IP drilldown
# ---------------------------------------------------------------------

st.markdown("---")
col_src, col_dst = st.columns(2)

with col_src:
    st.subheader("Top source IPs in queue")
    
    # Fill NaN country with "Internal" or "—" so groupby preserves rows
    alerts_src = alerts.copy()
    alerts_src["src_country_filled"] = alerts_src.apply(
        lambda r: r["src_country"] if pd.notna(r["src_country"]) 
                 else ("🏠 Internal" if r["src_internal"] else "—"),
        axis=1
    )
    
    src_summary = (
        alerts_src.groupby(["src_ip", "src_country_filled"])
        .agg(
            alerts=("event_id", "count"),
            max_priority=("priority_score", "max"),
            attack_families=("attack_family", lambda x: x.nunique()),
        )
        .reset_index()
        .sort_values("alerts", ascending=False)
        .head(10)
    )
    src_summary["max_priority"] = src_summary["max_priority"].astype(float).round(3)
    src_summary = src_summary.rename(columns={
        "src_ip": "Source IP",
        "src_country_filled": "Country",
        "alerts": "Alerts",
        "max_priority": "Max Score",
        "attack_families": "Families",
    })
    st.dataframe(
        src_summary, use_container_width=True, hide_index=True,
        column_config={
            "Max Score": st.column_config.ProgressColumn(
                "Max Score", min_value=0.0, max_value=1.0, format="%.3f"
            ),
        },
    )

with col_dst:
    st.subheader("Top targeted destinations")
    dst_summary = (
        alerts.groupby(["dest_ip", "dest_internal"])
        .agg(
            alerts=("event_id", "count"),
            max_priority=("priority_score", "max"),
            attack_families=("attack_family", lambda x: x.nunique()),
        )
        .reset_index()
        .sort_values("alerts", ascending=False)
        .head(10)
    )
    dst_summary["max_priority"] = dst_summary["max_priority"].astype(float).round(3)
    dst_summary["Type"] = dst_summary["dest_internal"].apply(
        lambda x: "🏠 Internal" if x else "🌐 External"
    )
    dst_summary = dst_summary.drop(columns=["dest_internal"])
    dst_summary = dst_summary[[
        "dest_ip", "Type", "alerts", "max_priority", "attack_families"
    ]].rename(columns={
        "dest_ip": "Destination IP",
        "alerts": "Alerts",
        "max_priority": "Max Score",
        "attack_families": "Families",
    })
    st.dataframe(
        dst_summary, use_container_width=True, hide_index=True,
        column_config={
            "Max Score": st.column_config.ProgressColumn(
                "Max Score", min_value=0.0, max_value=1.0, format="%.3f"
            ),
        },
    )

# ---------------------------------------------------------------------
# Section 4 — Family breakdown of current filter
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Attack family breakdown of current view")

family_summary = (
    alerts.groupby("attack_family")
    .agg(
        alerts=("event_id", "count"),
        avg_priority=("priority_score", "mean"),
        max_priority=("priority_score", "max"),
        avg_anomaly=("anomaly_score", "mean"),
    )
    .reset_index()
    .sort_values("alerts", ascending=False)
)
family_summary["avg_priority"] = family_summary["avg_priority"].astype(float).round(3)
family_summary["max_priority"] = family_summary["max_priority"].astype(float).round(3)
family_summary["avg_anomaly"] = family_summary["avg_anomaly"].astype(float).round(3)

family_summary = family_summary.rename(columns={
    "attack_family": "Family",
    "alerts": "Alerts",
    "avg_priority": "Avg Score",
    "max_priority": "Max Score",
    "avg_anomaly": "Avg Anomaly",
})

st.dataframe(
    family_summary, use_container_width=True, hide_index=True,
    column_config={
        "Avg Score": st.column_config.ProgressColumn(
            "Avg Score", min_value=0.0, max_value=1.0, format="%.3f"
        ),
        "Max Score": st.column_config.ProgressColumn(
            "Max Score", min_value=0.0, max_value=1.0, format="%.3f"
        ),
        "Avg Anomaly": st.column_config.ProgressColumn(
            "Avg Anomaly", min_value=0.0, max_value=1.0, format="%.3f"
        ),
    },
)

# ---------------------------------------------------------------------
# Section 5 — CSV export
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Export")

col_export1, col_export2 = st.columns([1, 4])
with col_export1:
    csv_data = alerts.to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download CSV",
        data=csv_data,
        file_name="soc_sentinel_alerts.csv",
        mime="text/csv",
        help=f"Export {len(alerts)} filtered alerts",
    )
with col_export2:
    st.caption(
        "Exports the current filtered alert list as CSV — useful for evidence collection, "
        "tickets, or further analysis."
    )

render_sidebar_footer()