"""
Extract stage — read cleaned CICIDS data from parquet snapshot.

The parquet file was produced by Week 1 EDA (notebook 01_cicids2017_eda).
This stage validates structure, applies sample mode if requested, and
hands off a typed DataFrame to the transform stage.
"""
from pathlib import Path
from typing import Optional

import duckdb
import pandas as pd

from src.etl.context import PipelineContext
from src.etl.logger import get_logger

logger = get_logger("extract")


# Expected columns — these MUST be in the parquet file or extract fails fast.
# This guards against silent schema drift from Week 1's EDA notebook.
REQUIRED_COLUMNS = {
    # Identity
    "Flow ID", "Source IP", "Destination IP",
    "Source Port", "Destination Port", "Protocol",
    # Time (note: raw Timestamp text was dropped during Week 1 cleaning;
    # only the parsed event_time survives)
    "event_time", "source_day",
    # Labels (only cleaned versions present — raw Label was dropped during Week 1 cleaning)
    "label_clean", "attack_family", "is_attack",
    # Core flow features (canary check — full feature list validated by column count)
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s",
}

EXPECTED_MIN_COLUMNS = 80    # cleaned parquet has 87
EXPECTED_MIN_ROWS = 3_000_000  # CICIDS2017 should be ~3.12M


def validate_schema(df: pd.DataFrame) -> None:
    """Fail fast if the parquet doesn't match expectations."""
    actual_cols = set(df.columns)
    missing = REQUIRED_COLUMNS - actual_cols
    if missing:
        raise ValueError(
            f"Parquet is missing required columns: {sorted(missing)}\n"
            f"Hint: re-run notebook 01_cicids2017_eda.ipynb to regenerate the snapshot."
        )

    if len(df.columns) < EXPECTED_MIN_COLUMNS:
        raise ValueError(
            f"Parquet has only {len(df.columns)} columns; expected at least {EXPECTED_MIN_COLUMNS}. "
            f"Looks like a partial export — re-run the EDA notebook."
        )


def validate_volume(df: pd.DataFrame, ctx: PipelineContext) -> None:
    """Volume sanity check (skipped in sample/test mode)."""
    if ctx.run_mode in ("full",) and len(df) < EXPECTED_MIN_ROWS:
        raise ValueError(
            f"Parquet has only {len(df):,} rows; expected at least {EXPECTED_MIN_ROWS:,}. "
            f"This looks incomplete — investigate before loading."
        )


def read_parquet_full(parquet_path: Path) -> pd.DataFrame:
    """Read entire parquet into a pandas DataFrame using DuckDB (faster than pd.read_parquet)."""
    logger.info(f"Reading {parquet_path.name} ({parquet_path.stat().st_size / 1e6:.1f} MB)")
    con = duckdb.connect()  # in-memory
    df = con.execute(
        f"SELECT * FROM read_parquet('{parquet_path.as_posix()}')"
    ).fetchdf()
    con.close()
    return df


def read_parquet_sampled(parquet_path: Path, sample_size: int) -> pd.DataFrame:
    """
    Read a stratified sample so all attack families are represented.

    Used for dev/test runs where loading 3M rows is overkill.
    """
    logger.info(f"Reading stratified sample (n={sample_size:,}) from {parquet_path.name}")
    con = duckdb.connect()
    df = con.execute(f"""
        WITH stratified AS (
            SELECT *,
                   ROW_NUMBER() OVER (PARTITION BY attack_family ORDER BY RANDOM()) AS rn
            FROM read_parquet('{parquet_path.as_posix()}')
        )
        SELECT * EXCLUDE (rn)
        FROM stratified
        WHERE rn <= {max(1, sample_size // 10)}    -- 10 attack families ≈ even split
    """).fetchdf()
    con.close()
    return df


def drop_invalid_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """
    Drop rows that can never be loaded (e.g., missing event_time).

    Note: rows with NULL labels are KEPT — they're the legitimate Unlabeled
    Thursday WebAttacks rows we identified in Week 1.
    """
    initial_count = len(df)

    # Must have a parseable timestamp — without it we can't resolve date_sk/time_sk
    df = df[df["event_time"].notna()].copy()

    # Must have valid IPs (they get resolved to dim_asset)
    df = df[df["Source IP"].notna() & df["Destination IP"].notna()].copy()

    dropped = initial_count - len(df)
    if dropped > 0:
        logger.warning(f"Dropped {dropped:,} invalid rows (missing timestamp or IPs)")
    return df, dropped


def run(ctx: PipelineContext) -> pd.DataFrame:
    """
    Main extract entry point.

    Returns the extracted DataFrame and updates ctx.rows_extracted.
    Also stores the DataFrame on ctx.extracted_df so downstream stages can access it.
    """
    parquet_path = ctx.input_parquet

    if not parquet_path.exists():
        raise FileNotFoundError(
            f"Cleaned CICIDS parquet not found at: {parquet_path}\n"
            f"Run notebooks/01_cicids2017_eda.ipynb to generate it."
        )

    # Read based on mode
    if ctx.run_mode == "full":
        df = read_parquet_full(parquet_path)
    elif ctx.run_mode in ("sample", "test"):
        sample_size = ctx.sample_size or 10_000
        df = read_parquet_sampled(parquet_path, sample_size)
    else:
        raise ValueError(f"Unknown run_mode: {ctx.run_mode}")

    logger.info(f"Loaded {len(df):,} rows × {len(df.columns)} columns into memory")

    # Validate schema
    validate_schema(df)
    logger.debug("Schema validation passed")

    # Volume check (only in full mode)
    validate_volume(df, ctx)

    # Drop unrecoverable rows
    df, dropped = drop_invalid_rows(df)

    # Update context
    ctx.extracted_df = df
    ctx.rows_extracted = len(df)

    # Quick distribution snapshot for the log
    if "attack_family" in df.columns:
        dist = df["attack_family"].value_counts().head(10).to_dict()
        logger.info(f"Attack family distribution (top): {dist}")

    return df