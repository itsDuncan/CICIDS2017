"""
Per-user behavioral baseline computation.

Computes baseline behavioral profile for each user using the first 60 days
of their activity. Then computes per-day deviation metrics for the remainder.

Output:
    - warehouse.user_baselines (new table) — one row per user
    - warehouse.user_daily_features (new table) — one row per (user, day)

These feed Phase 2 ML in Day 6.

Usage:
    python -m src.cert.baselines
"""
import argparse
import logging
import sys
import time
from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import text

from src.warehouse import get_engine

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)

# Baseline window — first N days of each user's activity
BASELINE_DAYS = 60


# ---------------------------------------------------------------------
# DDL — create the output tables
# ---------------------------------------------------------------------

def ensure_tables_exist():
    """Create user_baselines and user_daily_features tables if missing."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS warehouse.user_baselines (
                user_sk                    BIGINT PRIMARY KEY,
                baseline_from              DATE NOT NULL,
                baseline_to                DATE NOT NULL,
                baseline_active_days       SMALLINT NOT NULL,
                baseline_usb_per_day       NUMERIC(8,3),
                baseline_emails_per_day    NUMERIC(8,3),
                baseline_ext_emails_per_day NUMERIC(8,3),
                baseline_files_per_day     NUMERIC(8,3),
                baseline_logon_count       NUMERIC(8,3),
                baseline_after_hours_pct   NUMERIC(5,3),
                baseline_weekend_pct       NUMERIC(5,3),
                baseline_distinct_pcs      SMALLINT,
                baseline_avg_session_hours NUMERIC(6,2),
                computed_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS warehouse.user_daily_features (
                user_sk                    BIGINT NOT NULL,
                feature_date               DATE NOT NULL,
                day_of_week                SMALLINT,
                events_total               INTEGER,
                usb_connects               INTEGER,
                emails_sent                INTEGER,
                ext_emails                 INTEGER,
                file_accesses              INTEGER,
                logons                     INTEGER,
                after_hours_events         INTEGER,
                weekend_events             INTEGER,
                distinct_pcs               SMALLINT,
                in_attack_window           SMALLINT,
                PRIMARY KEY (user_sk, feature_date)
            )
        """))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_udf_user "
            "ON warehouse.user_daily_features(user_sk)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_udf_attack "
            "ON warehouse.user_daily_features(in_attack_window) "
            "WHERE in_attack_window = 1"
        ))
    logger.info("Tables ensured: user_baselines, user_daily_features")


# ---------------------------------------------------------------------
# Data extraction — fetch all user-day aggregates from fact table
# ---------------------------------------------------------------------

def fetch_user_daily_aggregates() -> pd.DataFrame:
    """
    Build one row per (user, day) with all behavioral metrics.

    Single query against fact_user_activity — keeps DB roundtrips minimal.
    """
    engine = get_engine()
    logger.info("Fetching per-user-day aggregates from fact table")
    t0 = time.time()

    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                f.user_sk,
                date_trunc('day', f.event_time)::date AS feature_date,
                EXTRACT(DOW FROM f.event_time)::int AS day_of_week,
                COUNT(*) AS events_total,
                SUM(CASE WHEN at.activity_name = 'Connect' THEN 1 ELSE 0 END) AS usb_connects,
                SUM(CASE WHEN at.activity_name = 'Email Send' THEN 1 ELSE 0 END) AS emails_sent,
                SUM(CASE WHEN at.activity_name = 'Email Send' 
                          AND f.external_recipient_count > 0 THEN 1 ELSE 0 END) AS ext_emails,
                SUM(CASE WHEN at.activity_name = 'File Access' THEN 1 ELSE 0 END) AS file_accesses,
                SUM(CASE WHEN at.activity_name = 'Logon' THEN 1 ELSE 0 END) AS logons,
                SUM(f.is_after_hours) AS after_hours_events,
                SUM(f.is_weekend) AS weekend_events,
                COUNT(DISTINCT f.asset_sk) AS distinct_pcs,
                MAX(f.in_attack_window) AS in_attack_window
            FROM warehouse.fact_user_activity f
            JOIN warehouse.dim_activity_type at ON at.activity_sk = f.activity_sk
            GROUP BY f.user_sk, date_trunc('day', f.event_time)::date,
                     EXTRACT(DOW FROM f.event_time)
        """), conn)

    df["feature_date"] = pd.to_datetime(df["feature_date"])
    logger.info(f"  {len(df):,} (user, day) rows in {time.time()-t0:.1f}s")
    return df


# ---------------------------------------------------------------------
# Baseline computation
# ---------------------------------------------------------------------

def compute_baselines(daily_df: pd.DataFrame) -> pd.DataFrame:
    """
    For each user, compute their baseline behavioral profile using the
    first BASELINE_DAYS calendar days of their activity.
    """
    logger.info(f"Computing baselines (first {BASELINE_DAYS} days per user)")
    t0 = time.time()

    baselines = []
    grouped = daily_df.groupby("user_sk")
    for user_sk, user_df in grouped:
        user_df = user_df.sort_values("feature_date")
        first_date = user_df["feature_date"].min()
        baseline_end = first_date + pd.Timedelta(days=BASELINE_DAYS)
        baseline_mask = user_df["feature_date"] < baseline_end
        bdf = user_df[baseline_mask]

        if bdf.empty:
            continue

        active_days = len(bdf)
        total_events = bdf["events_total"].sum()

        baselines.append({
            "user_sk": user_sk,
            "baseline_from": first_date.date(),
            "baseline_to": baseline_end.date(),
            "baseline_active_days": active_days,
            "baseline_usb_per_day":       round(bdf["usb_connects"].sum() / max(active_days, 1), 3),
            "baseline_emails_per_day":    round(bdf["emails_sent"].sum() / max(active_days, 1), 3),
            "baseline_ext_emails_per_day": round(bdf["ext_emails"].sum() / max(active_days, 1), 3),
            "baseline_files_per_day":     round(bdf["file_accesses"].sum() / max(active_days, 1), 3),
            "baseline_logon_count":       round(bdf["logons"].sum() / max(active_days, 1), 3),
            "baseline_after_hours_pct":   round(bdf["after_hours_events"].sum() / max(total_events, 1), 3),
            "baseline_weekend_pct":       round(bdf["weekend_events"].sum() / max(total_events, 1), 3),
            "baseline_distinct_pcs":      int(bdf["distinct_pcs"].max()) if len(bdf) > 0 else 0,
            "baseline_avg_session_hours": 0.0,  # placeholder — refined in Day 5
        })

    out = pd.DataFrame(baselines)
    logger.info(f"  Computed {len(out):,} baselines in {time.time()-t0:.1f}s")
    return out


# ---------------------------------------------------------------------
# Persistence — TRUNCATE + COPY
# ---------------------------------------------------------------------

def persist_baselines(baselines_df: pd.DataFrame) -> int:
    engine = get_engine()
    raw_conn = engine.raw_connection()
    try:
        cur = raw_conn.cursor()
        cur.execute("TRUNCATE warehouse.user_baselines")
        buf = StringIO()
        baselines_df.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)
        cur.copy_expert(
            "COPY warehouse.user_baselines (" + ", ".join(baselines_df.columns) +
            ") FROM STDIN WITH CSV NULL ''",
            buf,
        )
        n = cur.rowcount
        raw_conn.commit()
        cur.close()
    except Exception:
        raw_conn.rollback()
        raise
    finally:
        raw_conn.close()
    return n


def persist_daily_features(daily_df: pd.DataFrame) -> int:
    engine = get_engine()
    raw_conn = engine.raw_connection()
    try:
        cur = raw_conn.cursor()
        cur.execute("TRUNCATE warehouse.user_daily_features")
        cols_ordered = [
            "user_sk", "feature_date", "day_of_week",
            "events_total", "usb_connects", "emails_sent", "ext_emails",
            "file_accesses", "logons", "after_hours_events", "weekend_events",
            "distinct_pcs", "in_attack_window",
        ]
        out = daily_df[cols_ordered].copy()
        out["feature_date"] = out["feature_date"].dt.date.astype(str)
        buf = StringIO()
        out.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)
        cur.copy_expert(
            "COPY warehouse.user_daily_features (" + ", ".join(cols_ordered) +
            ") FROM STDIN WITH CSV NULL ''",
            buf,
        )
        n = cur.rowcount
        raw_conn.commit()
        cur.close()
    except Exception:
        raw_conn.rollback()
        raise
    finally:
        raw_conn.close()
    return n


# ---------------------------------------------------------------------
# Quick validation — does the baseline reveal what we hoped?
# ---------------------------------------------------------------------

def validate_separability():
    """
    Quick sanity check: do malicious users' attack-window days deviate
    more from baseline than legitimate users' typical days?
    """
    engine = get_engine()
    logger.info("Running separability validation")

    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH user_groups AS (
                SELECT
                    udf.user_sk,
                    udf.feature_date,
                    udf.usb_connects,
                    udf.ext_emails,
                    udf.after_hours_events,
                    udf.events_total,
                    udf.in_attack_window,
                    u.is_malicious,
                    u.malicious_scenario,
                    ub.baseline_usb_per_day,
                    ub.baseline_ext_emails_per_day,
                    ub.baseline_after_hours_pct
                FROM warehouse.user_daily_features udf
                JOIN warehouse.dim_user u ON u.user_sk = udf.user_sk
                LEFT JOIN warehouse.user_baselines ub ON ub.user_sk = udf.user_sk
                WHERE udf.feature_date >= ub.baseline_to  -- post-baseline only
            )
            SELECT
                CASE
                    WHEN is_malicious = 0 THEN 'Legitimate'
                    WHEN malicious_scenario = 1 AND in_attack_window = 1 THEN 'Scen 1 (attack day)'
                    WHEN malicious_scenario = 2 AND in_attack_window = 1 THEN 'Scen 2 (attack day)'
                    WHEN malicious_scenario = 3 AND in_attack_window = 1 THEN 'Scen 3 (attack day)'
                    ELSE 'Malicious (non-attack day)'
                END AS user_day_group,
                COUNT(*) AS user_days,
                ROUND(AVG(usb_connects)::numeric, 2) AS avg_usb,
                ROUND(AVG(usb_connects - baseline_usb_per_day)::numeric, 2) AS usb_deviation,
                ROUND(AVG(ext_emails)::numeric, 2) AS avg_ext_emails,
                ROUND(AVG(ext_emails - baseline_ext_emails_per_day)::numeric, 2) AS ext_email_deviation,
                ROUND(AVG(after_hours_events::float / NULLIF(events_total, 0) - baseline_after_hours_pct)::numeric, 3) AS after_hours_deviation
            FROM user_groups
            GROUP BY user_day_group
            ORDER BY user_day_group
        """), conn)

    logger.info("Baseline-deviation comparison:")
    print(df.to_string(index=False))
    return df


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    logger.info("=" * 60)
    logger.info("PER-USER BASELINE COMPUTATION")
    logger.info("=" * 60)

    t_start = time.time()
    ensure_tables_exist()

    daily_df = fetch_user_daily_aggregates()
    baselines_df = compute_baselines(daily_df)

    persisted_baselines = persist_baselines(baselines_df)
    persisted_daily = persist_daily_features(daily_df)

    print()
    print("=" * 60)
    print("BASELINE COMPUTATION SUMMARY")
    print("=" * 60)
    print(f"  user_baselines rows:        {persisted_baselines:,}")
    print(f"  user_daily_features rows:   {persisted_daily:,}")
    print(f"  Elapsed:                    {time.time() - t_start:.1f}s")
    print("=" * 60)

    print()
    print("=" * 60)
    print("SEPARABILITY VALIDATION — DEVIATION FROM BASELINE")
    print("=" * 60)
    validate_separability()
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())