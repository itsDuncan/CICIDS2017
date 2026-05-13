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

# =====================================================================
# Phase 2 — Insider Threat (CERT)
# =====================================================================


@st.cache_data(ttl=CACHE_TTL)
def get_phase2_kpis() -> dict:
    """Headline KPIs for Phase 2 user-level risk."""
    engine = get_engine()
    with engine.begin() as conn:
        # User risk score breakdown
        user_stats = conn.execute(text("""
            SELECT
                COUNT(*) AS total_users,
                SUM(is_malicious_truth) AS malicious_users_truth,
                SUM(CASE WHEN risk_label IN ('high', 'elevated') THEN 1 ELSE 0 END)
                    AS flagged_users,
                SUM(CASE WHEN risk_label IN ('high', 'elevated')
                          AND is_malicious_truth = 1 THEN 1 ELSE 0 END)
                    AS flagged_correctly
            FROM warehouse.user_risk_scores
        """)).fetchone()

        # Activity stats
        activity_stats = conn.execute(text("""
            SELECT
                COUNT(*) AS total_events,
                SUM(in_attack_window) AS attack_window_events,
                SUM(is_after_hours) AS after_hours_events,
                COUNT(DISTINCT user_sk) AS distinct_users
            FROM warehouse.fact_user_activity
        """)).fetchone()

    total = user_stats[0] or 0
    malicious = user_stats[1] or 0
    flagged = user_stats[2] or 0
    correct = user_stats[3] or 0

    return {
        "total_users":        int(total),
        "malicious_truth":    int(malicious),
        "flagged_users":      int(flagged),
        "flagged_correctly":  int(correct),
        "recall":             round(correct / max(malicious, 1) * 100, 1),
        "precision":          round(correct / max(flagged, 1) * 100, 1),
        "total_events":       int(activity_stats[0] or 0),
        "attack_window_events": int(activity_stats[1] or 0),
        "after_hours_events": int(activity_stats[2] or 0),
        "distinct_users":     int(activity_stats[3] or 0),
    }


@st.cache_data(ttl=CACHE_TTL)
def get_user_risk_leaderboard(
    min_score: float = 0.0,
    risk_filter: list = None,
    scenario_filter: list = None,
) -> pd.DataFrame:
    """
    All users with their risk scores. Joined to the LATEST SCD2 record
    per user (handles departed malicious users correctly).
    """
    where_parts = ["1=1"]
    if min_score > 0:
        where_parts.append(f"urs.risk_score >= {min_score}")
    if risk_filter:
        labels = ", ".join(f"'{r}'" for r in risk_filter)
        where_parts.append(f"urs.risk_label IN ({labels})")
    if scenario_filter:
        scens = ", ".join(str(s) for s in scenario_filter)
        where_parts.append(f"COALESCE(latest_u.malicious_scenario, 0) IN ({scens})")

    where_clause = " AND ".join(where_parts)
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text(f"""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id)
                    user_sk, user_id, employee_name, role, department, team,
                    supervisor_name, is_malicious, malicious_scenario,
                    attack_window_start, attack_window_end, is_current
                FROM warehouse.dim_user
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                latest_u.user_id,
                latest_u.employee_name,
                latest_u.role,
                latest_u.department,
                latest_u.team,
                latest_u.supervisor_name,
                latest_u.is_current AS employment_active,
                ROUND(urs.risk_score::numeric, 4) AS risk_score,
                urs.risk_label,
                urs.is_malicious_truth,
                latest_u.malicious_scenario,
                latest_u.attack_window_start,
                latest_u.attack_window_end
            FROM warehouse.user_risk_scores urs
            JOIN latest_user latest_u ON latest_u.user_sk = urs.user_sk
            WHERE {where_clause}
            ORDER BY urs.risk_score DESC
        """), conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_scenario_summary() -> pd.DataFrame:
    """Per-scenario detection breakdown."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id)
                    user_sk, malicious_scenario
                FROM warehouse.dim_user
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                COALESCE(latest_u.malicious_scenario, 0) AS scenario,
                COUNT(*) AS users,
                SUM(CASE WHEN urs.risk_label IN ('high', 'elevated') THEN 1 ELSE 0 END)
                    AS flagged,
                AVG(urs.risk_score) AS avg_risk_score,
                MAX(urs.risk_score) AS max_risk_score,
                MIN(urs.risk_score) AS min_risk_score
            FROM warehouse.user_risk_scores urs
            JOIN latest_user latest_u ON latest_u.user_sk = urs.user_sk
            GROUP BY COALESCE(latest_u.malicious_scenario, 0)
            ORDER BY scenario
        """), conn)
    df["catch_rate_pct"] = (df["flagged"] / df["users"] * 100).round(1)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_user_activity_timeline(user_id: str) -> pd.DataFrame:
    """Daily activity timeline for one user — uses latest SCD2 user_sk."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id) user_sk, attack_window_start,
                       attack_window_end, is_malicious, malicious_scenario
                FROM warehouse.dim_user
                WHERE user_id = :user_id
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                udml.feature_date,
                udml.events_total,
                udml.usb_connects,
                udml.emails_sent,
                udml.ext_emails,
                udml.file_accesses,
                udml.logons,
                udml.after_hours_events,
                udml.weekend_events,
                udml.usb_zscore_peer,
                udml.usb_ratio_personal,
                udml.multi_signal_count,
                udml.in_attack_window,
                ub.baseline_usb_per_day,
                ub.baseline_ext_emails_per_day,
                ub.baseline_after_hours_pct,
                lu.attack_window_start,
                lu.attack_window_end,
                lu.is_malicious,
                lu.malicious_scenario
            FROM latest_user lu
            JOIN warehouse.user_daily_ml_features udml ON udml.user_sk = lu.user_sk
            LEFT JOIN warehouse.user_baselines ub ON ub.user_sk = lu.user_sk
            ORDER BY udml.feature_date
        """), conn, params={"user_id": user_id})
    df["feature_date"] = pd.to_datetime(df["feature_date"])
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_user_search_options() -> pd.DataFrame:
    """All users (latest SCD2 record each) for drilldown search."""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT DISTINCT ON (user_id)
                user_id, employee_name, role, department, is_current
            FROM warehouse.dim_user
            ORDER BY user_id, valid_from DESC
        """), conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_user_profile(user_id: str) -> dict:
    """Complete profile for one user — latest SCD2 record."""
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id) *
                FROM warehouse.dim_user
                WHERE user_id = :user_id
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                u.user_id, u.employee_name, u.email_address,
                u.role, u.department, u.team, u.supervisor_name,
                u.business_unit, u.functional_unit, u.is_current,
                u.is_malicious, u.malicious_scenario,
                u.attack_window_start, u.attack_window_end,
                urs.risk_score, urs.risk_label,
                ub.baseline_usb_per_day, ub.baseline_emails_per_day,
                ub.baseline_ext_emails_per_day, ub.baseline_files_per_day,
                ub.baseline_after_hours_pct, ub.baseline_weekend_pct,
                ub.baseline_active_days, ub.baseline_from, ub.baseline_to
            FROM latest_user u
            LEFT JOIN warehouse.user_risk_scores urs ON urs.user_sk = u.user_sk
            LEFT JOIN warehouse.user_baselines ub ON ub.user_sk = u.user_sk
        """), {"user_id": user_id}).fetchone()
    if not result:
        return None
    return dict(result._mapping)

@st.cache_data(ttl=CACHE_TTL)
def get_scenario_behavioral_profile() -> pd.DataFrame:
    """
    Average post-baseline behavioral feature values per scenario.
    Used by the Scenarios page radar chart.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id) user_sk, malicious_scenario, is_malicious
                FROM warehouse.dim_user
                ORDER BY user_id, valid_from DESC
            ),
            user_aggregates AS (
                SELECT
                    lu.user_sk,
                    COALESCE(lu.malicious_scenario, 0) AS scenario,
                    AVG(udml.usb_connects::float) AS avg_usb,
                    AVG(udml.ext_emails::float) AS avg_ext_emails,
                    AVG(udml.file_accesses::float) AS avg_files,
                    AVG(udml.after_hours_pct::float) AS avg_after_hours_pct,
                    MAX(udml.usb_zscore_peer::float) AS max_usb_z,
                    MAX(udml.usb_ratio_personal::float) AS max_usb_ratio,
                    MAX(udml.multi_signal_count::float) AS max_signals
                FROM latest_user lu
                JOIN warehouse.user_daily_ml_features udml ON udml.user_sk = lu.user_sk
                JOIN warehouse.user_baselines ub ON ub.user_sk = lu.user_sk
                WHERE udml.feature_date >= ub.baseline_to
                GROUP BY lu.user_sk, lu.malicious_scenario
            )
            SELECT
                scenario,
                COUNT(*) AS users,
                AVG(avg_usb) AS avg_daily_usb,
                AVG(avg_ext_emails) AS avg_daily_ext_emails,
                AVG(avg_files) AS avg_daily_files,
                AVG(avg_after_hours_pct) AS avg_after_hours_pct,
                AVG(max_usb_z) AS avg_peak_usb_z,
                AVG(max_usb_ratio) AS avg_peak_usb_ratio,
                AVG(max_signals) AS avg_peak_signals
            FROM user_aggregates
            GROUP BY scenario
            ORDER BY scenario
        """), conn)
    return df


@st.cache_data(ttl=CACHE_TTL)
def get_malicious_users_detail() -> pd.DataFrame:
    """
    Every malicious user with their model verdict + attack window detail.
    Used by the Scenarios page caught/missed table.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id) *
                FROM warehouse.dim_user
                WHERE is_malicious = 1
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                lu.user_id,
                lu.employee_name,
                lu.role,
                lu.department,
                lu.malicious_scenario,
                lu.attack_window_start,
                lu.attack_window_end,
                (lu.attack_window_end::date - lu.attack_window_start::date) AS window_days,
                lu.is_current AS employment_active,
                ROUND(urs.risk_score::numeric, 4) AS risk_score,
                urs.risk_label,
                CASE WHEN urs.risk_label IN ('high', 'elevated') THEN 1 ELSE 0 END AS caught
            FROM latest_user lu
            JOIN warehouse.user_risk_scores urs ON urs.user_sk = lu.user_sk
            ORDER BY lu.malicious_scenario, urs.risk_score DESC
        """), conn)
    return df

@st.cache_data(ttl=CACHE_TTL)
def get_user_hourly_activity(user_id: str) -> pd.DataFrame:
    """
    Hour-of-day × day-of-week activity grid for one user.
    Used by the drilldown page heatmap.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH latest_user AS (
                SELECT DISTINCT ON (user_id) user_sk
                FROM warehouse.dim_user
                WHERE user_id = :user_id
                ORDER BY user_id, valid_from DESC
            )
            SELECT
                EXTRACT(HOUR FROM f.event_time)::int AS hour_24,
                EXTRACT(DOW FROM f.event_time)::int AS day_of_week,
                at.activity_category,
                COUNT(*) AS events
            FROM latest_user lu
            JOIN warehouse.fact_user_activity f ON f.user_sk = lu.user_sk
            JOIN warehouse.dim_activity_type at ON at.activity_sk = f.activity_sk
            GROUP BY hour_24, day_of_week, at.activity_category
        """), conn, params={"user_id": user_id})
    return df