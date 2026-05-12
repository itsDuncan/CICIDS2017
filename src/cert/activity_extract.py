"""
CERT activity event extractor.

Reads the 4 activity CSVs (logon, device, email, file), normalizes columns
into a unified schema, and writes a single parquet file for downstream
loading into fact_user_activity.

Why parquet intermediary:
    - Decouples parsing from DB loading (faster iteration)
    - Restartable: re-run loader without re-parsing 1.3 GB email.csv
    - Phase 1 used the same pattern successfully

Skipped:
    - http.csv (14.5 GB — Phase 2.5 stretch goal)
    - email.content + file.content (no analytical value, massive size)
"""
import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = PROJECT_ROOT / "data" / "raw" / "cert" / "r4.2"
INTERIM_DIR = PROJECT_ROOT / "data" / "interim"
INTERIM_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_PARQUET = INTERIM_DIR / "cert_activities_unified.parquet"


# ---------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------

def extract_logon() -> pd.DataFrame:
    """Logon events: 854,859 rows."""
    path = CERT_DIR / "logon.csv"
    logger.info(f"Reading {path.name}")
    t0 = time.time()

    df = pd.read_csv(path)
    df["date"] = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")

    # Standardize columns
    out = pd.DataFrame({
        "event_id_src":   df["id"],
        "event_time":     df["date"],
        "user_id":        df["user"],
        "pc_id":          df["pc"],
        "activity_type":  df["activity"],   # "Logon" or "Logoff"
        "filename":       None,
        "email_size":     None,
        "email_recipients_count": None,
        "email_attachments_count": None,
        "email_to_external_domain": None,
        "email_from_external_address": None,
    })

    logger.info(f"  Loaded {len(out):,} logon events in {time.time()-t0:.1f}s")
    return out


def extract_device() -> pd.DataFrame:
    """Device (USB) events: 405,380 rows."""
    path = CERT_DIR / "device.csv"
    logger.info(f"Reading {path.name}")
    t0 = time.time()

    df = pd.read_csv(path)
    df["date"] = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")

    out = pd.DataFrame({
        "event_id_src":   df["id"],
        "event_time":     df["date"],
        "user_id":        df["user"],
        "pc_id":          df["pc"],
        "activity_type":  df["activity"].map({  # USB-specific labels
            "Connect":    "USB_Connect",
            "Disconnect": "USB_Disconnect",
        }),
        "filename":       None,
        "email_size":     None,
        "email_recipients_count": None,
        "email_attachments_count": None,
        "email_to_external_domain": None,
        "email_from_external_address": None,
    })

    logger.info(f"  Loaded {len(out):,} device events in {time.time()-t0:.1f}s")
    return out


def extract_email() -> pd.DataFrame:
    """
    Email events: 2,629,979 rows. Largest file (1.3 GB).
    Drops content column; computes derived metadata flags.
    """
    path = CERT_DIR / "email.csv"
    logger.info(f"Reading {path.name} (1.3 GB — may take a minute)")
    t0 = time.time()

    # Skip the content column entirely — saves significant memory
    df = pd.read_csv(
        path,
        usecols=["id", "date", "user", "pc", "to", "cc", "bcc",
                 "from", "size", "attachments"],
    )
    df["date"] = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")

    # Derived: count of recipients (to + cc + bcc are semicolon-separated)
    def count_recipients(row):
        total = 0
        for col in ("to", "cc", "bcc"):
            val = row[col]
            if pd.notna(val) and val:
                total += val.count(";") + 1
        return total

    # Derived: email targeted at external domain (NOT @dtaa.com)
    # "to" can contain multiple addresses semicolon-separated
    def has_external_recipient(to_str):
        if pd.isna(to_str) or not to_str:
            return 0
        for addr in to_str.split(";"):
            addr = addr.strip().lower()
            if addr and "@dtaa.com" not in addr:
                return 1
        return 0

    # Derived: email from non-corporate address
    # If 'from' doesn't contain @dtaa.com, the user sent from a personal account
    def is_from_external(from_str):
        if pd.isna(from_str):
            return 0
        return 0 if "@dtaa.com" in from_str.lower() else 1

    out = pd.DataFrame({
        "event_id_src":   df["id"],
        "event_time":     df["date"],
        "user_id":        df["user"],
        "pc_id":          df["pc"],
        "activity_type":  "Email",
        "filename":       None,
        "email_size":     df["size"].astype("Int64"),
        "email_recipients_count": df.apply(count_recipients, axis=1).astype("Int64"),
        "email_attachments_count": df["attachments"].astype("Int64"),
        "email_to_external_domain": df["to"].map(has_external_recipient).astype("Int64"),
        "email_from_external_address": df["from"].map(is_from_external).astype("Int64"),
    })

    logger.info(f"  Loaded {len(out):,} email events in {time.time()-t0:.1f}s")
    return out


def extract_file() -> pd.DataFrame:
    """
    File events: 445,581 rows. Drops content column.
    """
    path = CERT_DIR / "file.csv"
    logger.info(f"Reading {path.name}")
    t0 = time.time()

    df = pd.read_csv(path, usecols=["id", "date", "user", "pc", "filename"])
    df["date"] = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")

    out = pd.DataFrame({
        "event_id_src":   df["id"],
        "event_time":     df["date"],
        "user_id":        df["user"],
        "pc_id":          df["pc"],
        "activity_type":  "File_Activity",
        "filename":       df["filename"],
        "email_size":     None,
        "email_recipients_count": None,
        "email_attachments_count": None,
        "email_to_external_domain": None,
        "email_from_external_address": None,
    })

    logger.info(f"  Loaded {len(out):,} file events in {time.time()-t0:.1f}s")
    return out


# ---------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------

def extract_all() -> pd.DataFrame:
    """Run all 4 extractors and concatenate."""
    logger.info("=" * 60)
    logger.info("CERT ACTIVITY EXTRACTION")
    logger.info("=" * 60)

    t_start = time.time()

    parts = [
        extract_logon(),
        extract_device(),
        extract_email(),
        extract_file(),
    ]

    logger.info("Concatenating sources")
    unified = pd.concat(parts, ignore_index=True)

    # Drop any rows where date parsing failed
    pre = len(unified)
    unified = unified.dropna(subset=["event_time"])
    if pre != len(unified):
        logger.warning(f"  Dropped {pre - len(unified):,} rows with unparseable dates")

    # Sort chronologically — helpful for downstream analysis
    unified = unified.sort_values("event_time").reset_index(drop=True)

    # Activity type breakdown
    logger.info("Activity type distribution:")
    for activity, count in unified["activity_type"].value_counts().items():
        logger.info(f"  {activity:<20} {count:>10,}")

    elapsed = time.time() - t_start
    logger.info(f"Total: {len(unified):,} rows in {elapsed:.1f}s")
    return unified


def save_parquet(df: pd.DataFrame, path: Path = OUTPUT_PARQUET):
    """Persist the unified frame for downstream loading."""
    logger.info(f"Writing parquet: {path}")
    t0 = time.time()
    df.to_parquet(path, compression="snappy", index=False)
    size_mb = path.stat().st_size / 1e6
    logger.info(f"  Wrote {size_mb:.1f} MB in {time.time()-t0:.1f}s")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract CERT activity events to unified parquet",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(OUTPUT_PARQUET),
        help=f"Output parquet path (default: {OUTPUT_PARQUET})",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    df = extract_all()
    save_parquet(df, Path(args.output))

    print()
    print("=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"  Output:          {args.output}")
    print(f"  Total events:    {len(df):,}")
    print(f"  Date range:      {df['event_time'].min()} to {df['event_time'].max()}")
    print(f"  Distinct users:  {df['user_id'].nunique():,}")
    print(f"  Distinct PCs:    {df['pc_id'].nunique():,}")
    print(f"  Activity types:  {df['activity_type'].nunique()}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())