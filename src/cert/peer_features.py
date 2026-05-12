"""
Peer-group deviation features.

For each (user, day), compute how that user's behavior compares to peers
on the same day. Peer = same role + department in the user's current
dim_user record.

This complements personal baselines:
    - Personal baseline: "different from how YOU normally act"
    - Peer deviation:    "different from how your COWORKERS act today"

Both signals are weak alone; both together are strong.

Usage:
    python -m src.cert.peer_features
"""
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


# ---------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------

def ensure_tables_exist():
    engine = get_engine()
    with engine.begin() as conn:
        # Final feature table — what Phase 2 ML will train on
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS warehouse.user_daily_ml_features (
                user_sk                BIGINT NOT NULL,
                feature_date           DATE NOT NULL,
                day_of_week            SMALLINT,

                -- Raw daily counts
                events_total           INTEGER,
                usb_connects           INTEGER,
                emails_sent            INTEGER,
                ext_emails             INTEGER,
                file_accesses          INTEGER,
                logons                 INTEGER,
                after_hours_events     INTEGER,
                weekend_events         INTEGER,
                distinct_pcs           SMALLINT,

                -- Personal-baseline deviations (today - baseline)
                usb_dev_personal       NUMERIC(8,3),
                emails_dev_personal    NUMERIC(8,3),
                ext_emails_dev_personal NUMERIC(8,3),
                files_dev_personal     NUMERIC(8,3),

                -- Personal-baseline ratios (today / baseline; capped at 50)
                usb_ratio_personal     NUMERIC(6,2),
                ext_emails_ratio_personal NUMERIC(6,2),

                -- Peer-group deviation z-scores (against same role/dept on same day)
                usb_zscore_peer        NUMERIC(8,3),
                ext_emails_zscore_peer NUMERIC(8,3),
                after_hours_zscore_peer NUMERIC(8,3),

                -- After-hours proportion of the day
                after_hours_pct        NUMERIC(5,3),

                -- Composite anomaly indicators
                multi_signal_count     SMALLINT,  -- count of metrics 2+ SD above norm

                -- Labels for training
                is_malicious_user      SMALLINT,
                in_attack_window       SMALLINT,
                malicious_scenario     SMALLINT,

                PRIMARY KEY (user_sk, feature_date)
            )
        """))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_udml_label "
            "ON warehouse.user_daily_ml_features(in_attack_window) "
            "WHERE in_attack_window = 1"
        ))
    logger.info("Table ensured: user_daily_ml_features")


# ---------------------------------------------------------------------
# Fetch all the inputs in one query
# ---------------------------------------------------------------------

def fetch_features_with_baselines() -> pd.DataFrame:
    engine = get_engine()
    logger.info("Loading daily features + baselines + user metadata")
    t0 = time.time()

    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                udf.user_sk,
                udf.feature_date,
                udf.day_of_week,
                udf.events_total,
                udf.usb_connects,
                udf.emails_sent,
                udf.ext_emails,
                udf.file_accesses,
                udf.logons,
                udf.after_hours_events,
                udf.weekend_events,
                udf.distinct_pcs,
                udf.in_attack_window,

                u.role,
                u.department,
                u.is_malicious,
                u.malicious_scenario,

                ub.baseline_usb_per_day,
                ub.baseline_emails_per_day,
                ub.baseline_ext_emails_per_day,
                ub.baseline_files_per_day,
                ub.baseline_to AS baseline_end
            FROM warehouse.user_daily_features udf
            JOIN warehouse.dim_user u ON u.user_sk = udf.user_sk
            LEFT JOIN warehouse.user_baselines ub ON ub.user_sk = udf.user_sk
        """), conn)

    df["feature_date"] = pd.to_datetime(df["feature_date"])
    df["baseline_end"] = pd.to_datetime(df["baseline_end"])
    logger.info(f"  {len(df):,} user-day rows loaded in {time.time()-t0:.1f}s")
    return df


# ---------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------

def compute_personal_deviations(df: pd.DataFrame) -> pd.DataFrame:
    """Personal-baseline (today - baseline) and (today / baseline) features."""
    logger.info("Computing personal-baseline deviations")

    df["usb_dev_personal"] = df["usb_connects"] - df["baseline_usb_per_day"].fillna(0)
    df["emails_dev_personal"] = df["emails_sent"] - df["baseline_emails_per_day"].fillna(0)
    df["ext_emails_dev_personal"] = df["ext_emails"] - df["baseline_ext_emails_per_day"].fillna(0)
    df["files_dev_personal"] = df["file_accesses"] - df["baseline_files_per_day"].fillna(0)

    # Ratios — cap at 50 to prevent infinity for users with 0 baseline
    df["usb_ratio_personal"] = np.minimum(
        df["usb_connects"] / df["baseline_usb_per_day"].replace(0, 0.1).fillna(0.1),
        50.0,
    )
    df["ext_emails_ratio_personal"] = np.minimum(
        df["ext_emails"] / df["baseline_ext_emails_per_day"].replace(0, 0.1).fillna(0.1),
        50.0,
    )

    df["after_hours_pct"] = (
        df["after_hours_events"].astype(float) / df["events_total"].clip(lower=1)
    )
    return df


def compute_peer_deviations(df: pd.DataFrame) -> pd.DataFrame:
    """
    Peer-group z-scores — for each (department, day), how far does this user
    deviate from their peers on that day?
    """
    logger.info("Computing peer-group deviations (this may take a moment)")
    t0 = time.time()

    # Group by (department, day) — compute mean and std of key metrics
    peer_groups = df.groupby(["department", "feature_date"])

    for col, zcol in [
        ("usb_connects",       "usb_zscore_peer"),
        ("ext_emails",         "ext_emails_zscore_peer"),
        ("after_hours_events", "after_hours_zscore_peer"),
    ]:
        group_mean = peer_groups[col].transform("mean")
        group_std = peer_groups[col].transform("std").replace(0, 1)  # avoid div by 0
        df[zcol] = ((df[col] - group_mean) / group_std).fillna(0)

    logger.info(f"  Peer deviations computed in {time.time()-t0:.1f}s")
    return df


def compute_composite(df: pd.DataFrame) -> pd.DataFrame:
    """Multi-signal count: how many features are 2+ SD above the user's baseline."""
    logger.info("Computing composite multi-signal indicator")

    df["multi_signal_count"] = (
        (df["usb_zscore_peer"] > 2).astype(int)
        + (df["ext_emails_zscore_peer"] > 2).astype(int)
        + (df["after_hours_zscore_peer"] > 2).astype(int)
        + (df["usb_ratio_personal"] > 3).astype(int)
        + (df["ext_emails_ratio_personal"] > 3).astype(int)
    ).astype("int16")
    return df


def assemble_output(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "user_sk", "feature_date", "day_of_week",
        "events_total", "usb_connects", "emails_sent", "ext_emails",
        "file_accesses", "logons", "after_hours_events", "weekend_events", "distinct_pcs",
        "usb_dev_personal", "emails_dev_personal", "ext_emails_dev_personal", "files_dev_personal",
        "usb_ratio_personal", "ext_emails_ratio_personal",
        "usb_zscore_peer", "ext_emails_zscore_peer", "after_hours_zscore_peer",
        "after_hours_pct", "multi_signal_count",
        "is_malicious", "in_attack_window", "malicious_scenario",
    ]
    out = df[cols].rename(columns={"is_malicious": "is_malicious_user"}).copy()

    # Type cleanup
    for c in ["usb_dev_personal", "emails_dev_personal", "ext_emails_dev_personal",
              "files_dev_personal", "usb_ratio_personal", "ext_emails_ratio_personal",
              "usb_zscore_peer", "ext_emails_zscore_peer", "after_hours_zscore_peer",
              "after_hours_pct"]:
        out[c] = out[c].round(3)

    # malicious_scenario can be NULL — fill with 0 for clarity
    out["malicious_scenario"] = out["malicious_scenario"].fillna(0).astype("int16")

    return out


# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

def persist(df: pd.DataFrame) -> int:
    engine = get_engine()
    raw_conn = engine.raw_connection()
    try:
        cur = raw_conn.cursor()
        cur.execute("TRUNCATE warehouse.user_daily_ml_features")

        out = df.copy()
        out["feature_date"] = out["feature_date"].dt.date.astype(str)

        buf = StringIO()
        out.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)
        cur.copy_expert(
            "COPY warehouse.user_daily_ml_features ("
            + ", ".join(out.columns) +
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
# Validation
# ---------------------------------------------------------------------

def validate():
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT
                CASE
                    WHEN is_malicious_user = 0 THEN 'Legitimate'
                    WHEN malicious_scenario = 1 AND in_attack_window = 1 THEN 'Scen 1 attack day'
                    WHEN malicious_scenario = 2 AND in_attack_window = 1 THEN 'Scen 2 attack day'
                    WHEN malicious_scenario = 3 AND in_attack_window = 1 THEN 'Scen 3 attack day'
                    ELSE 'Malicious non-attack'
                END AS user_day_group,
                COUNT(*) AS days,
                ROUND(AVG(usb_dev_personal)::numeric, 2) AS usb_dev,
                ROUND(AVG(usb_ratio_personal)::numeric, 2) AS usb_ratio,
                ROUND(AVG(usb_zscore_peer)::numeric, 2) AS usb_z_peer,
                ROUND(AVG(ext_emails_zscore_peer)::numeric, 2) AS ext_email_z_peer,
                ROUND(AVG(multi_signal_count::float)::numeric, 2) AS avg_signals_triggered
            FROM warehouse.user_daily_ml_features
            GROUP BY user_day_group
            ORDER BY user_day_group
        """), conn)
    print(df.to_string(index=False))


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    logger.info("=" * 60)
    logger.info("PHASE 2 ML FEATURE COMPUTATION")
    logger.info("=" * 60)
    t_start = time.time()

    ensure_tables_exist()
    df = fetch_features_with_baselines()
    df = compute_personal_deviations(df)
    df = compute_peer_deviations(df)
    df = compute_composite(df)
    out = assemble_output(df)

    n = persist(out)

    print()
    print("=" * 60)
    print("ML FEATURE COMPUTATION SUMMARY")
    print("=" * 60)
    print(f"  Rows written:  {n:,}")
    print(f"  Elapsed:       {time.time() - t_start:.1f}s")
    print("=" * 60)
    print()
    print("=" * 60)
    print("FEATURE SEPARABILITY VALIDATION")
    print("=" * 60)
    validate()
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())