"""
Geography page — world map of external IP origins and attacker locations.
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
    COLORS,
)
from app.data import (
    get_external_ip_geographic_distribution,
    get_geo_summary_stats,
    get_documented_attacker_details,
    get_internal_target_distribution,
    get_attack_flow_origin_dest,
)


# ---------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------

set_page_config(page_title="Geography", page_icon="🌍")
render_sidebar_header()

st.title("🌍 Geographic Threat Origins")
st.markdown(
    "Network footprint distribution by country. External IPs enriched via "
    "MaxMind GeoLite2 GeoIP database, with the documented CICIDS2017 attacker "
    "highlighted in red."
)

# ---------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------

with st.spinner("Loading geographic data..."):
    geo_stats = get_geo_summary_stats()
    country_df = get_external_ip_geographic_distribution()
    attacker_df = get_documented_attacker_details()

# ---------------------------------------------------------------------
# Section 1 — Top metrics
# ---------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "External IPs",
        format_compact(geo_stats["total_external_ips"]),
        help="Distinct non-internal IP addresses observed",
    )

with col2:
    st.metric(
        "Distinct Countries",
        geo_stats["distinct_countries"],
        help="Countries with at least one external IP",
    )

with col3:
    geo_coverage = (
        (geo_stats["total_external_ips"] - geo_stats["unmapped_ips"])
        / max(geo_stats["total_external_ips"], 1)
        * 100
    )
    st.metric(
        "Geo Coverage",
        f"{geo_coverage:.1f}%",
        delta=f"{geo_stats['unmapped_ips']:,} unmapped",
        delta_color="off",
        help="IPs successfully geolocated via GeoLite2",
    )

with col4:
    top_country = country_df.iloc[0] if not country_df.empty else None
    if top_country is not None:
        st.metric(
            "Top Country",
            f"{top_country['country_iso']}",
            delta=f"{format_compact(int(top_country['distinct_ips']))} IPs",
            delta_color="off",
            help=f"{top_country['country_name']}",
        )

st.markdown("---")

# ---------------------------------------------------------------------
# Section 2 — World choropleth
# ---------------------------------------------------------------------

st.subheader("Global IP distribution")

if not country_df.empty:
    fig = go.Figure(data=go.Choropleth(
        locations=country_df["country_iso"],
        z=country_df["distinct_ips"],
        text=country_df["country_name"],
        colorscale=[
            [0.0, "#1c2128"],
            [0.05, "#2d3a4d"],
            [0.2, "#4a6c8a"],
            [0.5, "#5a8da4"],
            [0.85, "#e9c46a"],
            [1.0, "#e63946"],
        ],
        autocolorscale=False,
        reversescale=False,
        marker_line_color="#0f1419",
        marker_line_width=0.5,
        colorbar=dict(
            title=dict(text="IPs", font=dict(color="#e6edf3")),
            tickfont=dict(color="#e6edf3"),
            len=0.6,
            thickness=15,
        ),
        zmax=country_df["distinct_ips"].quantile(0.95),  # Cap to avoid US dominating scale
        zmin=0,
        hovertemplate=(
            "<b>%{text}</b><br>"
            "%{z:,} unique IPs<extra></extra>"
        ),
    ))

    # Overlay attacker pin if available
    if not attacker_df.empty:
        documented = attacker_df[attacker_df["ip"] == "205.174.165.73"]
        if not documented.empty:
            doc = documented.iloc[0]
            fig.add_trace(
                go.Scattergeo(
                    lon=[float(doc["longitude"])],
                    lat=[float(doc["latitude"])],
                    mode="markers+text",
                    marker=dict(
                        size=18,
                        color="#e63946",
                        line=dict(width=2, color="white"),
                        symbol="x",
                    ),
                    name="Documented Attacker",
                    text=["Documented Attacker"],
                    textposition="top center",
                    textfont=dict(color="#e63946", size=11),
                    hovertemplate=(
                        f"<b>Documented CICIDS2017 Attacker</b><br>"
                        f"IP: 205.174.165.73<br>"
                        f"Location: {doc['city']}, {doc['country_name']}<br>"
                        f"Total attacks: {int(doc['attack_count']):,}<br>"
                        f"Unique targets: {int(doc['unique_targets']):,}<extra></extra>"
                    ),
                )
            )

    fig.update_geos(
        showcoastlines=True,
        coastlinecolor="#3a4250",
        showland=True,
        landcolor="#1c2128",
        showocean=True,
        oceancolor="#0a0f17",
        showcountries=True,
        countrycolor="#2a2f37",
        projection_type="natural earth",
        bgcolor="rgba(0,0,0,0)",
    )

    fig.update_layout(
        height=580,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "💡 Color scale is capped at the 95th percentile to prevent the United States "
        "from dominating the scale. Red ✕ marks the documented CICIDS2017 attacker "
        "(University of New Brunswick lab IP)."
    )
else:
    st.warning("No geographic data available.")

st.markdown("---")

# ---------------------------------------------------------------------
# Section 3 — Top countries table
# ---------------------------------------------------------------------

st.subheader("Top 20 countries by IP volume")

if not country_df.empty:
    top20 = country_df.head(20).copy()
    top20["pct"] = (
        top20["distinct_ips"] / country_df["distinct_ips"].sum() * 100
    ).round(2)
    top20["Rank"] = range(1, len(top20) + 1)

    display = top20[["Rank", "country_iso", "country_name", "distinct_ips", "pct"]].rename(
        columns={
            "country_iso": "ISO",
            "country_name": "Country",
            "distinct_ips": "Distinct IPs",
            "pct": "% of External",
        }
    )
    display["Distinct IPs"] = display["Distinct IPs"].apply(lambda x: f"{x:,}")
    display["% of External"] = display["% of External"].apply(lambda x: f"{x:.2f}%")

    st.dataframe(display, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------
# Section 4 — Documented attacker spotlight
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("Documented attacker spotlight")

if not attacker_df.empty:
    documented = attacker_df[attacker_df["ip"] == "205.174.165.73"]
    if not documented.empty:
        doc = documented.iloc[0]

        col_a, col_b, col_c = st.columns([2, 1, 1])

        with col_a:
            st.markdown(
                f"""
                **IP**: `205.174.165.73`
                **Location**: {doc['city']}, {doc['country_name']}
                **Coordinates**: {float(doc['latitude']):.4f}°N, {float(doc['longitude']):.4f}°W
                **ASN**: {doc['asn_org'] or 'Unknown'}
                """
            )

        with col_b:
            st.metric(
                "Total Attacks",
                format_compact(int(doc["attack_count"])),
                help="Events sourced from this IP",
            )

        with col_c:
            st.metric(
                "Unique Targets",
                int(doc["unique_targets"]),
                help="Distinct internal IPs attacked",
            )

        st.info(
            "🎯 **Provenance**: This IP belongs to the **University of New Brunswick**, "
            "which created CICIDS2017. It served as the lab's attacker host. "
            "Despite generating the entire attack volume in this dataset, its `AbuseIPDB` "
            "reputation score is `None` — correctly identifying it as research traffic, "
            "not a malicious actor."
        )

# ---------------------------------------------------------------------
# Section 5 — Internal target distribution
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("🎯 Internal targets — who got attacked")
st.caption(
    "Internal IPs in the CICIDS2017 lab network (RFC 1918 private space) that received "
    "attack traffic. These hosts have no real-world geographic location, so they're shown "
    "as a ranked inventory of the attacker's victims."
)

with st.spinner("Loading internal targets..."):
    targets_df = get_internal_target_distribution()

if not targets_df.empty:
    col_targets1, col_targets2 = st.columns([3, 2])

    with col_targets1:
        # Bar chart of attacks per internal target
        top_targets = targets_df.head(15)

        fig = go.Figure(data=[
            go.Bar(
                y=top_targets["internal_ip"],
                x=top_targets["attack_count"],
                orientation="h",
                marker=dict(
                    color=top_targets["attack_count"],
                    colorscale=[
                        [0.0, "#2d3a4d"],
                        [0.5, "#e9c46a"],
                        [1.0, "#e63946"],
                    ],
                    showscale=False,
                ),
                text=top_targets["attack_count"].apply(lambda x: f"{x:,}"),
                textposition="outside",
                textfont=dict(color="#e6edf3", size=11),
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "%{x:,} attacks<br>"
                    "<extra></extra>"
                ),
            )
        ])
        fig.update_layout(
            title=dict(
                text=f"Top 15 internal targets (of {len(targets_df)} total)",
                font=dict(color="#e6edf3", size=14),
            ),
            xaxis=dict(
                title="Attack events received",
                color="#a3b1c2",
                gridcolor="#2a2f37",
            ),
            yaxis=dict(
                autorange="reversed",
                color="#e6edf3",
            ),
            height=480,
            margin=dict(l=10, r=100, t=40, b=40),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_targets2:
        st.markdown("**Key target profiles**")

        # Known target descriptions from CICIDS2017 docs
        target_descriptions = {
            "192.168.10.50": "🌐 **Primary web server**\nTarget of DDoS, DoS, Web Attack, and Heartbleed scenarios.",
            "192.168.10.51": "🩸 **Heartbleed victim**\nTarget of the 20-minute Heartbleed exploitation window.",
            "192.168.10.8":  "🦠 **Compromised host**\nInfiltration source on Thursday afternoon.",
            "192.168.10.5":  "🤖 **Bot-compromised**\nPart of Friday's botnet cluster.",
            "192.168.10.9":  "🤖 **Bot-compromised**\nPart of Friday's botnet cluster.",
            "192.168.10.14": "🤖 **Bot-compromised**\nPart of Friday's botnet cluster.",
            "192.168.10.15": "🤖 **Bot-compromised**\nPart of Friday's botnet cluster.",
        }

        for ip, description in target_descriptions.items():
            row = targets_df[targets_df["internal_ip"] == ip]
            if not row.empty:
                count = int(row.iloc[0]["attack_count"])
                st.markdown(
                    f"**`{ip}`** — {format_compact(count)} attacks\n\n"
                    f"{description}\n"
                )
                st.markdown("")  # spacing

# ---------------------------------------------------------------------
# Section 6 — Attack flow visualization
# ---------------------------------------------------------------------

st.markdown("---")
st.subheader("🔀 Attack flow map — external sources to internal targets")
st.caption(
    "Arc lines show attack flows from external IPs to internal targets. "
    "Internal IPs (192.168.10.0/24) are positioned at the University of New Brunswick "
    "campus — the actual physical location of the CICIDS2017 lab network. "
    "Line thickness encodes attack volume (logarithmic scale)."
)

import numpy as np  # for log scaling

with st.spinner("Loading attack flow data..."):
    flow_df = get_attack_flow_origin_dest()

if flow_df.empty:
    st.info("No external attack flows recorded.")
else:
    # UNB campus coordinates (where the lab network physically lives)
    UNB_LAT = 45.9476
    UNB_LON = -66.6431

    # Aggregate per-source for the source markers (since one source may hit multiple targets)
    source_summary = (
        flow_df.groupby(["src_ip", "src_lat", "src_lon",
                         "src_country_iso", "src_country", "src_city"])
        .agg(
            total_attacks=("attack_count", "sum"),
            targets_hit=("dest_ip", "nunique"),
            attack_families=("attack_families", "sum"),
        )
        .reset_index()
        .sort_values("total_attacks", ascending=False)
    )

    # Unique targets for target markers
    target_summary = (
        flow_df.groupby("dest_ip")
        .agg(total_attacks=("attack_count", "sum"))
        .reset_index()
        .sort_values("total_attacks", ascending=False)
    )

    # Number-of-arcs cap for visual clarity (top flows only)
    MAX_ARCS = 100
    flow_display = flow_df.head(MAX_ARCS).copy()
    max_flow = flow_display["attack_count"].max()

    # Build the figure
    flow_fig = go.Figure()

    # Layer 1: Curved arcs (lines)
    # Plotly's Scattergeo with mode='lines' draws geodesics automatically
    for _, row in flow_display.iterrows():
        # Log-scale line width: gentle for small flows, bold for large
        log_attacks = np.log10(row["attack_count"] + 1)
        log_max = np.log10(max_flow + 1)
        width = 0.5 + 4.5 * (log_attacks / log_max)
        opacity = 0.25 + 0.55 * (log_attacks / log_max)

        flow_fig.add_trace(
            go.Scattergeo(
                lon=[float(row["src_lon"]), UNB_LON],
                lat=[float(row["src_lat"]), UNB_LAT],
                mode="lines",
                line=dict(width=width, color="#e63946"),
                opacity=opacity,
                showlegend=False,
                hoverinfo="skip",
            )
        )

    # Layer 2: Source markers (external attackers)
    # Size encodes attack volume (sqrt scale)
    src_sizes = (
        np.sqrt(source_summary["total_attacks"].clip(lower=1))
        / np.sqrt(source_summary["total_attacks"].max())
        * 22
        + 4
    )

    flow_fig.add_trace(
        go.Scattergeo(
            lon=source_summary["src_lon"].astype(float),
            lat=source_summary["src_lat"].astype(float),
            mode="markers",
            marker=dict(
                size=src_sizes,
                color="#e63946",
                line=dict(width=1.5, color="white"),
                opacity=0.85,
            ),
            name="Attack source",
            text=[
                f"<b>{ip}</b><br>"
                f"{city or '?'}, {country}<br>"
                f"{attacks:,} attacks<br>"
                f"{targets} internal targets hit"
                for ip, city, country, attacks, targets in zip(
                    source_summary["src_ip"],
                    source_summary["src_city"],
                    source_summary["src_country"],
                    source_summary["total_attacks"],
                    source_summary["targets_hit"],
                )
            ],
            hovertemplate="%{text}<extra></extra>",
        )
    )

    # Layer 3: Single target marker at UNB campus
    # All internal targets aggregated to a single highlighted point
    flow_fig.add_trace(
        go.Scattergeo(
            lon=[UNB_LON],
            lat=[UNB_LAT],
            mode="markers+text",
            marker=dict(
                size=24,
                color="#f4a261",
                symbol="square",
                line=dict(width=2, color="white"),
                opacity=0.95,
            ),
            text=["UNB Lab Network"],
            textposition="top center",
            textfont=dict(color="#f4a261", size=12),
            name="Internal target network",
            hovertemplate=(
                f"<b>UNB Lab Network (192.168.10.0/24)</b><br>"
                f"{len(target_summary)} targeted internal IPs<br>"
                f"{target_summary['total_attacks'].sum():,} total attack events<extra></extra>"
            ),
        )
    )

    # Auto-fit the geo bounds to include all sources + UNB
    all_lats = list(source_summary["src_lat"].astype(float).values) + [UNB_LAT]
    all_lons = list(source_summary["src_lon"].astype(float).values) + [UNB_LON]
    lat_padding = (max(all_lats) - min(all_lats)) * 0.1 + 5
    lon_padding = (max(all_lons) - min(all_lons)) * 0.1 + 5

    flow_fig.update_geos(
        showcoastlines=True,
        coastlinecolor="#3a4250",
        showland=True,
        landcolor="#1c2128",
        showocean=True,
        oceancolor="#0a0f17",
        showcountries=True,
        countrycolor="#2a2f37",
        projection_type="natural earth",
        bgcolor="rgba(0,0,0,0)",
        lonaxis=dict(range=[min(all_lons) - lon_padding, max(all_lons) + lon_padding]),
        lataxis=dict(range=[min(all_lats) - lat_padding, max(all_lats) + lat_padding]),
    )

    flow_fig.update_layout(
        height=580,
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(
            yanchor="top", y=0.98,
            xanchor="left", x=0.02,
            bgcolor="rgba(15,20,25,0.85)",
            bordercolor="#3a4250",
            borderwidth=1,
            font=dict(color="#e6edf3", size=11),
        ),
        showlegend=True,
    )
    st.plotly_chart(flow_fig, use_container_width=True)

    # Show flow summary below the map
    col_flow1, col_flow2, col_flow3 = st.columns(3)

    with col_flow1:
        st.metric(
            "Source IPs attacking",
            format_compact(len(source_summary)),
            help="Distinct external IPs that sent attack traffic",
        )

    with col_flow2:
        st.metric(
            "Internal targets",
            format_compact(len(target_summary)),
            help="Distinct internal IPs that received attacks",
        )

    with col_flow3:
        st.metric(
            "Total flows shown",
            format_compact(min(len(flow_df), MAX_ARCS)),
            delta=f"of {len(flow_df):,} total" if len(flow_df) > MAX_ARCS else None,
            delta_color="off",
            help=f"Top {MAX_ARCS} flows by attack volume",
        )

    # Top-flows table
    st.markdown("**Top 10 attack flows (by volume)**")
    top_flows = flow_df.head(10).copy()
    top_flows_display = top_flows[[
        "src_ip", "src_country", "dest_ip", "attack_count", "first_seen", "last_seen"
    ]].rename(columns={
        "src_ip": "Source IP",
        "src_country": "Source Country",
        "dest_ip": "Internal Target",
        "attack_count": "Attacks",
        "first_seen": "First Seen",
        "last_seen": "Last Seen",
    })
    top_flows_display["Attacks"] = top_flows_display["Attacks"].apply(lambda x: f"{x:,}")
    st.dataframe(top_flows_display, use_container_width=True, hide_index=True)

render_sidebar_footer()