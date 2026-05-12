"""
Load CERT activity events into fact_user_activity.

Pipeline:
    1. Read cert_activities_unified.parquet
    2. Ensure CERT PCs exist in dim_asset (insert if missing)
    3. Build FK lookup tables (user_sk via SCD2, activity_sk, asset_sk)
    4. Process in chunks:
       a. Resolve all FKs
       b. Derive file_extension, is_after_hours, is_weekend
       c. Denormalize is_malicious_user + in_attack_window
       d. COPY to fact_user_activity
    5. Validate

Usage:
    python -m src.cert.activity_load
    python -m src.cert.activity_load --truncate
    python -m src.cert.activity_load --chunk-size 500000
"""
import argparse
import logging
import sys
import time
from io import StringIO
from pathlib import Path
from typing import Optional

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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_PARQUET = PROJECT_ROOT / "data" / "interim" / "cert_activities_unified.parquet"

# Our extractor names → dim_activity_type.activity_name
ACTIVITY_NAME_MAP = {
    "Logon":           "Logon",
    "Logoff":          "Logoff",
    "USB_Connect":     "Connect",
    "USB_Disconnect":  "Disconnect",
    "Email":           "Email Send",
    "File_Activity":   "File Access",
}


# ---------------------------------------------------------------------
# Phase 1: Dimension preparation
# ---------------------------------------------------------------------

def ensure_cert_pcs_in_dim_asset(parquet_df: pd.DataFrame) -> dict:
    """
    Make sure every distinct CERT PC has a dim_asset row.
    Returns: dict mapping pc_id → asset_sk
    """
    engine = get_engine()
    distinct_pcs = sorted(parquet_df["pc_id"].dropna().unique())
    logger.info(f"Found {len(distinct_pcs):,} distinct CERT PCs")

    with engine.begin() as conn:
        # Find which already exist
        existing = pd.read_sql(text("""
            SELECT asset_identifier, asset_sk
            FROM warehouse.dim_asset
            WHERE asset_identifier = ANY(:pc_list)
        """), conn, params={"pc_list": distinct_pcs})

        existing_map = dict(zip(existing["asset_identifier"], existing["asset_sk"]))
        missing = [pc for pc in distinct_pcs if pc not in existing_map]

        if missing:
            logger.info(f"  Inserting {len(missing):,} new CERT PCs")
            insert_df = pd.DataFrame({
                "asset_identifier": missing,
                "asset_type":       "Workstation",
                "is_internal":      1,
                "source_system":    "CERT_r4.2",
            })

            buf = StringIO()
            insert_df.to_csv(buf, index=False, header=False, na_rep="")
            buf.seek(0)

            raw_conn = engine.raw_connection()
            try:
                cur = raw_conn.cursor()
                cur.copy_expert(
                    "COPY warehouse.dim_asset "
                    "(asset_identifier, asset_type, is_internal, source_system) "
                    "FROM STDIN WITH CSV NULL ''",
                    buf,
                )
                raw_conn.commit()
                cur.close()
            finally:
                raw_conn.close()

            # Refetch with the new SKs
            existing = pd.read_sql(text("""
                SELECT asset_identifier, asset_sk
                FROM warehouse.dim_asset
                WHERE asset_identifier = ANY(:pc_list)
            """), conn, params={"pc_list": distinct_pcs})
            existing_map = dict(zip(existing["asset_identifier"], existing["asset_sk"]))
        else:
            logger.info(f"  All PCs already in dim_asset")

    return existing_map


def load_activity_type_map() -> dict:
    """activity_name → activity_sk"""
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT activity_name, activity_sk
            FROM warehouse.dim_activity_type
        """), conn)
    return dict(zip(df["activity_name"], df["activity_sk"]))


def load_user_scd2_map() -> pd.DataFrame:
    """
    Load full SCD2 dim_user for in-memory join.

    Note: dim_user uses 9999-12-31 as sentinel for "still current", but pandas
    timestamps cap out at 2262-04-11. We clamp to 2099-12-31 — still far beyond
    any CERT event date so the comparison logic is preserved.
    """
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(text("""
            SELECT user_id, user_sk,
                   valid_from,
                   CASE WHEN valid_to >= '2262-01-01'::date THEN '2099-12-31'::date
                        ELSE valid_to END AS valid_to,
                   is_malicious, attack_window_start, attack_window_end
            FROM warehouse.dim_user
        """), conn)
    df["valid_from"]          = pd.to_datetime(df["valid_from"])
    df["valid_to"]            = pd.to_datetime(df["valid_to"])
    df["attack_window_start"] = pd.to_datetime(df["attack_window_start"])
    df["attack_window_end"]   = pd.to_datetime(df["attack_window_end"])
    logger.info(f"Loaded {len(df):,} dim_user rows for SCD2 resolution")
    return df


# ---------------------------------------------------------------------
# Phase 2: Chunked processing
# ---------------------------------------------------------------------

def derive_file_extension(filename: pd.Series) -> pd.Series:
    """'EYPC9Y08.doc' → 'doc'. Empty/NaN → None."""
    return (
        filename
        .fillna("")
        .str.extract(r"\.([A-Za-z0-9]+)$", expand=False)
        .str.lower()
        .where(lambda s: s.notna() & (s != ""), None)
    )


def derive_temporal_flags(event_time: pd.Series) -> tuple[pd.Series, pd.Series]:
    """
    Returns (is_after_hours, is_weekend) flags.

    after_hours = 1 if event happened outside 9 AM - 5 PM
    weekend     = 1 if Saturday or Sunday
    """
    hour = event_time.dt.hour
    dow  = event_time.dt.dayofweek  # Monday=0 ... Sunday=6
    is_after_hours = ((hour < 9) | (hour >= 17)).astype("Int8")
    is_weekend = (dow >= 5).astype("Int8")
    return is_after_hours, is_weekend


def process_chunk(
    chunk: pd.DataFrame,
    user_scd2: pd.DataFrame,
    pc_map: dict,
    activity_map: dict,
) -> pd.DataFrame:
    """
    Resolve FKs, derive flags, return ready-to-COPY DataFrame.
    """
    # FK: activity_sk
    chunk["activity_sk"] = (
        chunk["activity_type"]
        .map(ACTIVITY_NAME_MAP)
        .map(activity_map)
        .astype("Int16")
    )

    # FK: asset_sk
    chunk["asset_sk"] = chunk["pc_id"].map(pc_map).astype("Int64")

    # FK: date_sk (YYYYMMDD integer)
    chunk["date_sk"] = (
        chunk["event_time"].dt.year * 10000
        + chunk["event_time"].dt.month * 100
        + chunk["event_time"].dt.day
    ).astype("Int32")

    # FK: time_sk (hour * 60 + minute)
    chunk["time_sk"] = (
        chunk["event_time"].dt.hour * 60 + chunk["event_time"].dt.minute
    ).astype("Int16")

    # SCD2 user_sk + malicious flags
    # Use merge_asof: for each event, find dim_user row where event_time is in range
    chunk_sorted = chunk.sort_values("event_time").reset_index()
    user_sorted = user_scd2.sort_values("valid_from").reset_index(drop=True)

    # Per-user range join
    merged = pd.merge_asof(
        chunk_sorted,
        user_sorted,
        left_on="event_time",
        right_on="valid_from",
        left_by="user_id",
        right_by="user_id",
        direction="backward",
    )
    # Filter: only valid where event_time < valid_to
    merged = merged[merged["event_time"] < merged["valid_to"]]
    # Restore original chunk order
    merged = merged.sort_values("index").reset_index(drop=True)

    # Denormalized malicious flags
    merged["is_malicious_user"] = merged["is_malicious"].fillna(0).astype("Int8")
    merged["in_attack_window"] = (
        (merged["is_malicious"] == 1)
        & (merged["event_time"] >= merged["attack_window_start"])
        & (merged["event_time"] <= merged["attack_window_end"])
    ).astype("Int8")

    # Derived columns
    merged["file_extension"] = derive_file_extension(merged["filename"])
    is_after_hours, is_weekend = derive_temporal_flags(merged["event_time"])
    merged["is_after_hours"] = is_after_hours
    merged["is_weekend"] = is_weekend

    # Final output frame matching fact_user_activity columns
    out = pd.DataFrame({
        "source_system":            "CERT_r4.2",
        "date_sk":                  merged["date_sk"],
        "time_sk":                  merged["time_sk"],
        "user_sk":                  merged["user_sk"].astype("Int64"),
        "asset_sk":                 merged["asset_sk"],
        "activity_sk":              merged["activity_sk"],
        "natural_event_id":         merged["event_id_src"],
        "event_time":               merged["event_time"],
        "filename":                 merged["filename"],
        "file_extension":           merged["file_extension"],
        "to_recipients_count":      merged["email_recipients_count"].astype("Int16"),
        "external_recipient_count": merged["email_to_external_domain"].astype("Int16"),
        "attachment_count":         merged["email_attachments_count"].astype("Int16"),
        "size_bytes":               merged["email_size"].astype("Int64"),
        "url_domain":               None,  # populated only if http.csv is loaded
        "is_after_hours":           merged["is_after_hours"],
        "is_weekend":               merged["is_weekend"],
        "is_malicious_user":        merged["is_malicious_user"],
        "in_attack_window":         merged["in_attack_window"],
    })

    # Drop rows where critical FKs failed to resolve
    pre = len(out)
    out = out.dropna(subset=["user_sk", "activity_sk", "date_sk", "time_sk"])
    if pre != len(out):
        logger.warning(f"  Dropped {pre - len(out):,} rows with unresolvable FKs")

    return out


# ---------------------------------------------------------------------
# Phase 3: Bulk COPY
# ---------------------------------------------------------------------

def copy_chunk_to_warehouse(chunk_out: pd.DataFrame) -> int:
    """COPY a processed chunk into fact_user_activity."""
    engine = get_engine()
    raw_conn = engine.raw_connection()
    cols = list(chunk_out.columns)

    try:
        cur = raw_conn.cursor()
        buf = StringIO()
        chunk_out.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)
        cur.copy_expert(
            f"COPY warehouse.fact_user_activity ({', '.join(cols)}) "
            f"FROM STDIN WITH CSV NULL ''",
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
# Main orchestration
# ---------------------------------------------------------------------

def truncate_fact() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        logger.info("TRUNCATE warehouse.fact_user_activity")
        conn.execute(text("TRUNCATE warehouse.fact_user_activity RESTART IDENTITY"))


def run(chunk_size: int = 250_000, do_truncate: bool = True) -> dict:
    """Main loading pipeline."""
    logger.info("=" * 60)
    logger.info("CERT ACTIVITY LOAD INTO fact_user_activity")
    logger.info("=" * 60)

    t_start = time.time()

    # 1. Load parquet
    logger.info(f"Reading {INPUT_PARQUET.name}")
    df = pd.read_parquet(INPUT_PARQUET)
    logger.info(f"  {len(df):,} events ready")

    # 2. Ensure CERT PCs exist in dim_asset
    pc_map = ensure_cert_pcs_in_dim_asset(df)

    # 3. Load lookup tables
    activity_map = load_activity_type_map()
    user_scd2 = load_user_scd2_map()

    # 4. Optionally truncate
    if do_truncate:
        truncate_fact()

    # 5. Chunked processing + COPY
    total_loaded = 0
    n_chunks = (len(df) + chunk_size - 1) // chunk_size

    for i in range(n_chunks):
        t_chunk = time.time()
        start_idx = i * chunk_size
        end_idx = min(start_idx + chunk_size, len(df))
        chunk = df.iloc[start_idx:end_idx].copy()

        processed = process_chunk(chunk, user_scd2, pc_map, activity_map)
        loaded = copy_chunk_to_warehouse(processed)
        total_loaded += loaded

        rate = loaded / max(time.time() - t_chunk, 0.001)
        progress_pct = 100 * (i + 1) / n_chunks
        logger.info(
            f"  Chunk {i+1}/{n_chunks}: {loaded:,} loaded "
            f"({rate:.0f} rows/s) — {progress_pct:.0f}% complete"
        )

    elapsed = time.time() - t_start
    return {
        "rows_input":  len(df),
        "rows_loaded": total_loaded,
        "elapsed":     elapsed,
        "rate":        total_loaded / max(elapsed, 0.001),
    }


def validate() -> dict:
    """Post-load quality checks."""
    engine = get_engine()
    with engine.begin() as conn:
        return pd.read_sql(text("""
            SELECT
                COUNT(*) AS total_rows,
                COUNT(DISTINCT user_sk) AS distinct_users,
                SUM(is_malicious_user) AS malicious_user_events,
                SUM(in_attack_window) AS in_attack_window_events,
                SUM(is_after_hours) AS after_hours_events,
                MIN(event_time) AS earliest,
                MAX(event_time) AS latest,
                COUNT(DISTINCT activity_sk) AS activity_types_used
            FROM warehouse.fact_user_activity
        """), conn).iloc[0].to_dict()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Load CERT activities into fact_user_activity",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=250_000,
        help="Rows per processing chunk (default: 250000)",
    )
    parser.add_argument(
        "--no-truncate", action="store_true",
        help="Append instead of truncate",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    result = run(
        chunk_size=args.chunk_size,
        do_truncate=not args.no_truncate,
    )

    stats = validate()

    print()
    print("=" * 60)
    print("CERT ACTIVITY LOAD SUMMARY")
    print("=" * 60)
    print(f"  Rows input:                {result['rows_input']:,}")
    print(f"  Rows loaded:               {result['rows_loaded']:,}")
    print(f"  Elapsed:                   {result['elapsed']:.1f}s")
    print(f"  Throughput:                {result['rate']:.0f} rows/sec")
    print(f"\n  Warehouse validation:")
    print(f"    Total in fact:           {stats['total_rows']:,}")
    print(f"    Distinct users:          {stats['distinct_users']:,}")
    print(f"    Activity types used:     {stats['activity_types_used']}")
    print(f"    Malicious user events:   {stats['malicious_user_events']:,}")
    print(f"    In attack window:        {stats['in_attack_window_events']:,}")
    print(f"    After-hours events:      {stats['after_hours_events']:,}")
    print(f"    Date range:              {stats['earliest']} to {stats['latest']}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())