"""
LDAP loader — populates warehouse.dim_user with SCD2 history.

The CERT r4.2 dataset includes 19 monthly LDAP snapshots (2009-12 through 2011-05).
Each snapshot is the company directory at that point in time. Users come and go,
get promoted, change teams.

This loader produces a Slowly-Changing Dimension Type 2 (SCD2) population of
dim_user, where each row represents a (user, time period) — fact_user_activity
joins on user_sk that's valid for the event's date.

Output rows:
    user_sk         BIGSERIAL — surrogate primary key
    user_id         business key (e.g., 'CEL0561')
    employee_name, email, role, business_unit, functional_unit,
                   department, team, supervisor — versioned attributes
    effective_from  date this version began
    effective_to    date this version ended ('9999-12-31' if still current)
    is_current      1 if this is the latest record for that user

Usage (CLI):
    python -m src.cert.ldap_loader
    python -m src.cert.ldap_loader --truncate    # default
    python -m src.cert.ldap_loader --no-truncate # append (rare)
"""
import argparse
import logging
import re
import sys
import time
from datetime import date, datetime, timedelta
from io import StringIO
from pathlib import Path

import pandas as pd
from sqlalchemy import text

from src.warehouse import get_engine

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LDAP_DIR = PROJECT_ROOT / "data" / "raw" / "cert" / "r4.2" / "LDAP"

# Columns that, when changed, trigger a new SCD2 row
# CERT CSV column → warehouse column mapping
# (CSV column name on left, target table column name on right)
COLUMN_MAP = {
    "employee_name": "employee_name",
    "email":         "email_address",
    "role":          "role",
    "business_unit": "business_unit",
    "functional_unit": "functional_unit",
    "department":    "department",
    "team":          "team",
    "supervisor":    "supervisor_name",
}

# Source CSV columns whose changes trigger a new SCD2 row
TRACKED_ATTRIBUTES = list(COLUMN_MAP.keys())

# Far-future sentinel for "still active"
FAR_FUTURE = date(9999, 12, 31)


# ---------------------------------------------------------------------
# Snapshot loading
# ---------------------------------------------------------------------

def parse_snapshot_date(filename: str) -> date:
    """Extract date from filename like '2010-01.csv' → 2010-01-01."""
    m = re.match(r"(\d{4})-(\d{2})\.csv", filename)
    if not m:
        raise ValueError(f"Unexpected LDAP filename: {filename}")
    year, month = int(m.group(1)), int(m.group(2))
    return date(year, month, 1)


def load_all_snapshots() -> list[dict]:
    """
    Load every LDAP CSV from the directory, sorted by date.

    Returns a list of dicts:
        [{'snapshot_date': date, 'df': pd.DataFrame}, ...]
    """
    snapshots = []
    csv_files = sorted(LDAP_DIR.glob("*.csv"))
    logger.info(f"Found {len(csv_files)} LDAP snapshot files")

    for csv in csv_files:
        snapshot_date = parse_snapshot_date(csv.name)
        df = pd.read_csv(csv)

        # Normalize whitespace just in case
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].astype(str).str.strip()

        snapshots.append({"snapshot_date": snapshot_date, "df": df})
        logger.info(f"  {snapshot_date}: {len(df):,} rows")

    return snapshots


# ---------------------------------------------------------------------
# SCD2 computation
# ---------------------------------------------------------------------

def build_scd2_rows(snapshots: list[dict]) -> pd.DataFrame:
    """
    Walk through snapshots chronologically and emit SCD2 rows.

    Algorithm:
        For each user, track current attribute values.
        When a snapshot shows changed attributes, close current row
        (valid_to = snapshot_date) and open a new row.
        When a user disappears from a snapshot, close their current row.
        At the end, still-open rows get valid_to = FAR_FUTURE, is_current = 1.
    """
    logger.info("Computing SCD2 rows from snapshots")

    # State: user_id -> dict with current row's valid_from + source-named attributes
    current_state: dict[str, dict] = {}
    closed_rows: list[dict] = []

    for snapshot in snapshots:
        snap_date = snapshot["snapshot_date"]
        snap_df = snapshot["df"]

        snap_users = {row["user_id"]: row for _, row in snap_df.iterrows()}
        users_in_snap = set(snap_users.keys())
        users_in_state = set(current_state.keys())

        # 1. Users who disappeared this snapshot → close their record
        disappeared = users_in_state - users_in_snap
        for user_id in disappeared:
            state = current_state.pop(user_id)
            closed_rows.append({
                **state,
                "user_id": user_id,
                "valid_to": snap_date,
                "is_current": 0,
            })

        # 2. Users in this snapshot — check for changes or new arrivals
        for user_id, row in snap_users.items():
            attrs = {col: row.get(col, None) for col in TRACKED_ATTRIBUTES}

            if user_id not in current_state:
                current_state[user_id] = {
                    **attrs,
                    "valid_from": snap_date,
                }
            else:
                state = current_state[user_id]
                current_attrs = {col: state.get(col) for col in TRACKED_ATTRIBUTES}
                if current_attrs != attrs:
                    closed_rows.append({
                        **state,
                        "user_id": user_id,
                        "valid_to": snap_date,
                        "is_current": 0,
                    })
                    current_state[user_id] = {
                        **attrs,
                        "valid_from": snap_date,
                    }

    # 3. Any users still in state at end → close with FAR_FUTURE, is_current=1
    for user_id, state in current_state.items():
        closed_rows.append({
            **state,
            "user_id": user_id,
            "valid_to": FAR_FUTURE,
            "is_current": 1,
        })

    # Build dataframe with source column names
    df = pd.DataFrame(closed_rows)

    # Rename source columns to match table columns
    df = df.rename(columns=COLUMN_MAP)

    # Add required NOT NULL warehouse columns
    df["is_malicious"]   = 0
    df["source_system"]  = "CERT_r4.2"
    df["created_at"]     = datetime.now()

    # Reorder columns to match the COPY target column list exactly
    df = df[[
        "user_id",
        "employee_name", "email_address", "role",
        "business_unit", "functional_unit",
        "department", "team", "supervisor_name",
        "valid_from", "valid_to", "is_current",
        "is_malicious", "source_system", "created_at",
    ]]

    df = df.sort_values(["user_id", "valid_from"]).reset_index(drop=True)

    logger.info(
        f"Generated {len(df):,} SCD2 rows "
        f"({df['user_id'].nunique():,} distinct users, "
        f"{df['is_current'].sum():,} currently active)"
    )
    return df

# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

def load_to_warehouse(scd2_df: pd.DataFrame, truncate: bool = True) -> int:
    """
    Bulk-load SCD2 rows into warehouse.dim_user using PostgreSQL COPY.
    """
    engine = get_engine()
    raw_conn = engine.raw_connection()
    rows_loaded = 0

    try:
        cur = raw_conn.cursor()

        # Optional truncate
        if truncate:
            logger.info("TRUNCATE warehouse.dim_user RESTART IDENTITY CASCADE")
            cur.execute("TRUNCATE warehouse.dim_user RESTART IDENTITY CASCADE")

        # Build CSV buffer in memory
        buf = StringIO()
        scd2_df.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)

        # COPY
        cols = ", ".join(scd2_df.columns)
        logger.info(f"COPY {len(scd2_df):,} rows into dim_user")
        t0 = time.time()
        cur.copy_expert(
            f"COPY warehouse.dim_user ({cols}) FROM STDIN WITH CSV NULL ''",
            buf,
        )
        rows_loaded = cur.rowcount
        raw_conn.commit()
        logger.info(f"  Loaded {rows_loaded:,} rows in {time.time() - t0:.1f}s")

        cur.close()
    except Exception:
        raw_conn.rollback()
        raise
    finally:
        raw_conn.close()

    return rows_loaded


# ---------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------

def validate_load() -> dict:
    """Post-load sanity checks."""
    engine = get_engine()
    with engine.begin() as conn:
        stats = pd.read_sql(text("""
            SELECT
                COUNT(*) AS total_rows,
                COUNT(DISTINCT user_id) AS distinct_users,
                SUM(is_current) AS currently_active,
                MIN(valid_from) AS earliest_from,
                MAX(valid_to) FILTER (WHERE valid_to < '9999-01-01') AS latest_to,
                AVG(CASE WHEN valid_to = '9999-12-31' THEN NULL
                         ELSE (valid_to - valid_from) END)::int AS avg_period_days
            FROM warehouse.dim_user
        """), conn)
    return stats.iloc[0].to_dict()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Load CERT LDAP snapshots into warehouse.dim_user (SCD2)",
    )
    parser.add_argument(
        "--no-truncate",
        action="store_true",
        help="Append to dim_user instead of truncating first (rarely used)",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    truncate = not args.no_truncate

    logger.info("=" * 60)
    logger.info("LDAP SCD2 LOAD")
    logger.info("=" * 60)

    t0 = time.time()

    # 1. Load snapshots
    snapshots = load_all_snapshots()
    if not snapshots:
        logger.error(f"No LDAP files found in {LDAP_DIR}")
        return 1

    # 2. Build SCD2 rows
    scd2_df = build_scd2_rows(snapshots)

    # 3. Load to warehouse
    rows_loaded = load_to_warehouse(scd2_df, truncate=truncate)

    # 4. Validate
    stats = validate_load()
    elapsed = time.time() - t0

    print()
    print("=" * 60)
    print("LDAP LOAD SUMMARY")
    print("=" * 60)
    print(f"  Rows loaded:        {rows_loaded:,}")
    print(f"  Distinct users:     {stats['distinct_users']:,}")
    print(f"  Currently active:   {stats['currently_active']:,}")
    print(f"  Earliest effective: {stats['earliest_from']}")
    print(f"  Latest closed:      {stats['latest_to']}")
    print(f"  Avg period (days):  {stats['avg_period_days']}")
    print(f"  Elapsed:            {elapsed:.1f}s")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())