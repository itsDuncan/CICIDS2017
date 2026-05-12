"""
Data access layer for the SOC Sentinel dashboard.

All warehouse queries live here, cached aggressively to keep the UI snappy.
Pages never import sqlalchemy directly — they call functions from this module.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from sqlalchemy import text

# Make project importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.warehouse import get_engine  # noqa: E402

logger = logging.getLogger(__name__)


# Cache duration: 1 hour for slow-changing dashboards
CACHE_TTL = 3600


# ---------------------------------------------------------------------
# Warehouse health checks
# ---------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL)
def get_warehouse_stats() -> dict:
    """Total row counts across key tables. Cached 1 hour."""
    engine = get_engine()
    with engine.begin() as conn:
        stats = pd.read_sql("""
            SELECT 'fact_security_event' AS table_name, COUNT(*) AS rows
              FROM warehouse.fact_security_event
            UNION ALL SELECT 'dim_asset', COUNT(*) FROM warehouse.dim_asset
            UNION ALL SELECT 'dim_port', COUNT(*) FROM warehouse.dim_port
            UNION ALL SELECT 'dim_attack_type', COUNT(*) FROM warehouse.dim_attack_type
        """, conn)
        latest_scored = conn.execute(
            text("SELECT MAX(scored_at) FROM warehouse.fact_security_event")
        ).scalar()
    return {
        "tables": dict(zip(stats["table_name"], stats["rows"])),
        "latest_scored_at": latest_scored,
    }


# ---------------------------------------------------------------------
# Executive KPIs
# ---------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL)
def get_priority_distribution() -> pd.DataFrame:
    """
    Priority label counts across the warehouse.
    Returns columns: priority_label, events, pct.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT
                priority_label,
                COUNT(*) AS events,
                ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct
            FROM warehouse.fact_security_event
            WHERE priority_label IS NOT NULL
            GROUP BY priority_label
        """, conn)
    # Sort by severity order, not alphabetical
    order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    df["sort_order"] = df["priority_label"].map(order)
    return df.sort_values("sort_order").drop(columns="sort_order").reset_index(drop=True)


@st.cache_data(ttl=CACHE_TTL)
def get_attack_family_distribution() -> pd.DataFrame:
    """
    Attack family distribution across the warehouse.
    Used by the executive summary.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT
                attack_family_denorm AS family,
                COUNT(*) AS events,
                ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct,
                SUM(CASE WHEN priority_label IN ('critical', 'high') THEN 1 ELSE 0 END)
                    AS alert_count
            FROM warehouse.fact_security_event
            WHERE attack_family_denorm IS NOT NULL
            GROUP BY attack_family_denorm
            ORDER BY events DESC
        """, conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_headline_kpis() -> dict:
    """Single-number KPIs for the summary cards."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(text("""
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN priority_label = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN priority_label = 'high' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN attack_family_denorm <> 'Benign' THEN 1 ELSE 0 END) AS attack_count,
                COUNT(DISTINCT src_asset_sk) AS unique_src_ips,
                COUNT(DISTINCT dest_asset_sk) AS unique_dest_ips
            FROM warehouse.fact_security_event
        """)).fetchone()
    return {
        "total_events":   int(result[0] or 0),
        "critical_count": int(result[1] or 0),
        "high_count":     int(result[2] or 0),
        "attack_count":   int(result[3] or 0),
        "unique_src":     int(result[4] or 0),
        "unique_dest":    int(result[5] or 0),
    }


# ---------------------------------------------------------------------
# Timeline data
# ---------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL)
def get_attack_timeline_hourly() -> pd.DataFrame:
    """Hourly attack counts grouped by family — fast via materialized view."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT
                date_trunc('hour', f.event_time) AS hour_bucket,
                f.attack_family_denorm AS family,
                COUNT(*) AS events
            FROM warehouse.fact_security_event f
            WHERE f.attack_family_denorm IS NOT NULL
              AND f.attack_family_denorm <> 'Benign'
            GROUP BY date_trunc('hour', f.event_time), f.attack_family_denorm
            ORDER BY hour_bucket, family
        """, conn)
    return df


# ---------------------------------------------------------------------
# Geographic data
# ---------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL)
def get_top_attackers_by_country() -> pd.DataFrame:
    """External IP attacker volume by country."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT
                country_iso, country_name,
                attack_count,
                unique_targets, attack_families_used,
                first_seen, last_seen
            FROM warehouse.mv_top_attackers
            WHERE country_iso IS NOT NULL
            ORDER BY attack_count DESC
        """, conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_external_ip_geographic_distribution() -> pd.DataFrame:
    """
    Distribution of all external IPs by country
    (not just attackers — provides context for the geographic map).
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT
                country_iso, country_name,
                COUNT(*) AS distinct_ips
            FROM warehouse.dim_asset
            WHERE is_internal = 0 AND country_iso IS NOT NULL
            GROUP BY country_iso, country_name
            ORDER BY distinct_ips DESC
        """, conn)
    return df


# ---------------------------------------------------------------------
# Heatmap data
# ---------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL)
def get_hourly_heatmap() -> pd.DataFrame:
    """Hour-of-day × day-of-week heatmap data from materialized view."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql("""
            SELECT day_name, hour_24, attack_family, event_count
            FROM warehouse.mv_hourly_threat_pattern
        """, conn)
    return df


# ---------------------------------------------------------------------
# Alert queue
# ---------------------------------------------------------------------

@st.cache_data(ttl=300)  # 5 min — alerts are time-sensitive
def get_top_alerts(
    limit: int = 100,
    priority_filter: list = None,
    family_filter: list = None,
    src_country_filter: list = None,
    min_priority: float = 0.0,
) -> pd.DataFrame:
    """
    Top priority alerts with rich context for analyst review.

    Args:
        limit: max rows
        priority_filter: list of priority_label values to include
        family_filter: list of attack families to include
        src_country_filter: list of source country ISOs to include
        min_priority: minimum priority_score (default 0.0 = no filter)
    """
    where_parts = ["f.priority_label IS NOT NULL"]

    if priority_filter:
        labels_str = ", ".join(f"'{p}'" for p in priority_filter)
        where_parts.append(f"f.priority_label IN ({labels_str})")

    if family_filter:
        families_str = ", ".join(f"'{p}'" for p in family_filter)
        where_parts.append(f"f.attack_family_denorm IN ({families_str})")

    if src_country_filter:
        countries_str = ", ".join(f"'{p}'" for p in src_country_filter)
        where_parts.append(f"sa.country_iso IN ({countries_str})")

    if min_priority > 0:
        where_parts.append(f"f.priority_score >= {min_priority}")

    where_clause = " AND ".join(where_parts)

    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text(f"""
            SELECT
                f.event_id,
                f.event_time,
                sa.asset_identifier AS src_ip,
                sa.country_iso AS src_country,
                sa.is_internal AS src_internal,
                da.asset_identifier AS dest_ip,
                da.country_iso AS dest_country,
                da.is_internal AS dest_internal,
                f.attack_family_denorm AS attack_family,
                ROUND(f.priority_score::numeric, 4) AS priority_score,
                f.priority_label,
                ROUND(f.anomaly_score::numeric, 4) AS anomaly_score,
                f.flow_duration,
                f.total_fwd_packets,
                f.total_bwd_packets,
                f.is_attack
            FROM warehouse.fact_security_event f
            JOIN warehouse.dim_asset sa ON f.src_asset_sk = sa.asset_sk
            JOIN warehouse.dim_asset da ON f.dest_asset_sk = da.asset_sk
            WHERE {where_clause}
            ORDER BY f.priority_score DESC, f.event_time DESC
            LIMIT {limit}
        """), conn)
    return df

@st.cache_data(ttl=CACHE_TTL)
def get_alert_filter_options() -> dict:
    """
    Distinct values used to populate filter dropdowns on the Alerts page.
    """
    engine = get_engine()
    with engine.begin() as conn:
        families = pd.read_sql(text("""
            SELECT DISTINCT attack_family_denorm AS family
            FROM warehouse.fact_security_event
            WHERE attack_family_denorm IS NOT NULL
            ORDER BY family
        """), conn)
        countries = pd.read_sql(text("""
            SELECT DISTINCT sa.country_iso AS iso, sa.country_name AS name
            FROM warehouse.fact_security_event f
            JOIN warehouse.dim_asset sa ON f.src_asset_sk = sa.asset_sk
            WHERE sa.country_iso IS NOT NULL
              AND f.priority_label IN ('critical', 'high')
            ORDER BY sa.country_iso
        """), conn)
    return {
        "families": families["family"].tolist(),
        "countries": countries.set_index("iso")["name"].to_dict(),
    }

@st.cache_data(ttl=CACHE_TTL)
def get_documented_attacker_details() -> pd.DataFrame:
    """
    Detailed info for the known attacker IPs.
    Includes geo coordinates for plotting.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                a.asset_identifier AS ip,
                a.country_iso, a.country_name, a.city,
                a.latitude, a.longitude,
                a.asn_org, a.is_known_attacker,
                COUNT(f.event_id) AS attack_count,
                COUNT(DISTINCT f.dest_asset_sk) AS unique_targets
            FROM warehouse.dim_asset a
            JOIN warehouse.fact_security_event f ON f.src_asset_sk = a.asset_sk
            WHERE a.is_internal = 0
              AND f.is_attack = 1
              AND a.country_iso IS NOT NULL
            GROUP BY a.asset_identifier, a.country_iso, a.country_name,
                     a.city, a.latitude, a.longitude, a.asn_org, a.is_known_attacker
            HAVING COUNT(f.event_id) > 0
            ORDER BY attack_count DESC
            LIMIT 100
        """), conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_geo_summary_stats() -> dict:
    """Headline geographic stats for the page summary cards."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(text("""
            SELECT
                COUNT(DISTINCT asset_identifier) AS total_external_ips,
                COUNT(DISTINCT country_iso) AS distinct_countries,
                COUNT(DISTINCT CASE WHEN country_iso IS NULL THEN asset_identifier END)
                    AS unmapped_ips
            FROM warehouse.dim_asset
            WHERE is_internal = 0
        """)).fetchone()
    return {
        "total_external_ips": int(result[0] or 0),
        "distinct_countries": int(result[1] or 0),
        "unmapped_ips":       int(result[2] or 0),
    }

@st.cache_data(ttl=CACHE_TTL)
def get_internal_target_distribution() -> pd.DataFrame:
    """
    Internal IPs attacked and the volume of attacks against each.
    Used by the Geography page's 'targets' view.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                a.asset_identifier AS internal_ip,
                COUNT(f.event_id) AS attack_count,
                COUNT(DISTINCT f.src_asset_sk) AS unique_attackers,
                COUNT(DISTINCT f.attack_sk) AS attack_types_seen
            FROM warehouse.dim_asset a
            JOIN warehouse.fact_security_event f ON f.dest_asset_sk = a.asset_sk
            WHERE a.is_internal = 1
              AND f.is_attack = 1
            GROUP BY a.asset_identifier
            ORDER BY attack_count DESC
        """), conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_attack_flow_origin_dest() -> pd.DataFrame:
    """
    Aggregated attack flows for the arc visualization.

    Returns external source -> internal target with attack count,
    family breakdown, and properly grouped for clean visualization.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                sa.asset_identifier AS src_ip,
                sa.latitude AS src_lat,
                sa.longitude AS src_lon,
                sa.country_iso AS src_country_iso,
                sa.country_name AS src_country,
                sa.city AS src_city,
                da.asset_identifier AS dest_ip,
                COUNT(f.event_id) AS attack_count,
                COUNT(DISTINCT f.attack_sk) AS attack_families,
                MIN(f.event_time) AS first_seen,
                MAX(f.event_time) AS last_seen
            FROM warehouse.fact_security_event f
            JOIN warehouse.dim_asset sa ON sa.asset_sk = f.src_asset_sk
            JOIN warehouse.dim_asset da ON da.asset_sk = f.dest_asset_sk
            WHERE f.is_attack = 1
              AND sa.is_internal = 0
              AND da.is_internal = 1
              AND sa.latitude IS NOT NULL
              AND sa.longitude IS NOT NULL
            GROUP BY sa.asset_identifier, sa.latitude, sa.longitude,
                     sa.country_iso, sa.country_name, sa.city, da.asset_identifier
            ORDER BY attack_count DESC
        """), conn)
    return df

@st.cache_data(ttl=CACHE_TTL)
def get_working_hours_summary() -> pd.DataFrame:
    """
    Attack volume split by working hours (9 AM - 5 PM) vs after-hours.
    Used by the Heatmap page's comparison section.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                CASE 
                    WHEN t.hour_24 BETWEEN 9 AND 16 THEN 'Working hours (9 AM - 5 PM)'
                    ELSE 'After hours'
                END AS time_period,
                at.attack_family,
                COUNT(*) AS events
            FROM warehouse.fact_security_event f
            JOIN warehouse.dim_time t ON f.time_sk = t.time_sk
            JOIN warehouse.dim_attack_type at ON f.attack_sk = at.attack_sk
            WHERE f.is_attack = 1
            GROUP BY time_period, at.attack_family
        """), conn)
    return df