"""
Flag malicious users in dim_user from insiders.csv.

Reads insiders.csv, filters to CERT r4.2 (our dataset), and UPDATEs
warehouse.dim_user with:
    is_malicious        = 1
    malicious_scenario  = 1 | 2 | 3
    attack_window_start = scenario start timestamp
    attack_window_end   = scenario end timestamp

Usage:
    python -m src.cert.flag_malicious_users
"""
import logging
import sys
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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSIDERS_CSV = PROJECT_ROOT / "data" / "raw" / "cert" / "answers" / "insiders.csv"


def load_r42_malicious() -> pd.DataFrame:
    """Read insiders.csv and filter to CERT r4.2 rows."""
    if not INSIDERS_CSV.exists():
        raise FileNotFoundError(f"insiders.csv not found at {INSIDERS_CSV}")

    df = pd.read_csv(INSIDERS_CSV)
    logger.info(f"Loaded {len(df)} total insider records across all CERT releases")

    # Filter to r4.2
    r42 = df[df["dataset"].astype(str) == "4.2"].copy()
    logger.info(f"  CERT r4.2 insiders: {len(r42)}")

    # Parse timestamps (CERT uses M/D/YYYY format, sometimes leading-zero MM/DD/YYYY)
    r42["start"] = pd.to_datetime(r42["start"], errors="coerce")
    r42["end"] = pd.to_datetime(r42["end"], errors="coerce")

    bad_dates = r42[r42["start"].isna() | r42["end"].isna()]
    if not bad_dates.empty:
        logger.warning(f"  {len(bad_dates)} rows have unparseable dates — skipping them")
        r42 = r42.dropna(subset=["start", "end"])

    # Scenario breakdown
    scenario_counts = r42["scenario"].value_counts().sort_index()
    logger.info("  Scenario distribution:")
    for scenario, count in scenario_counts.items():
        logger.info(f"    Scenario {scenario}: {count} users")

    return r42[["user", "scenario", "start", "end"]].rename(columns={"user": "user_id"})


def flag_users(malicious_df: pd.DataFrame) -> dict:
    """UPDATE dim_user rows for each malicious user."""
    engine = get_engine()
    updated = 0
    not_found = []

    with engine.begin() as conn:
        for _, row in malicious_df.iterrows():
            result = conn.execute(
                text("""
                    UPDATE warehouse.dim_user
                    SET is_malicious        = 1,
                        malicious_scenario  = :scenario,
                        attack_window_start = :start,
                        attack_window_end   = :end
                    WHERE user_id = :user_id
                """),
                {
                    "user_id":  row["user_id"],
                    "scenario": int(row["scenario"]),
                    "start":    row["start"],
                    "end":      row["end"],
                },
            )
            if result.rowcount > 0:
                updated += result.rowcount
            else:
                not_found.append(row["user_id"])

    return {
        "rows_updated": updated,
        "not_found":    not_found,
    }


def validate() -> dict:
    """Confirm the flagging worked correctly."""
    engine = get_engine()
    with engine.begin() as conn:
        stats = pd.read_sql(text("""
            SELECT
                COUNT(*) FILTER (WHERE is_malicious = 1) AS malicious_users,
                COUNT(*) FILTER (WHERE is_malicious = 0) AS legitimate_users,
                COUNT(*) FILTER (WHERE is_malicious = 1 AND malicious_scenario = 1)
                    AS scenario_1_users,
                COUNT(*) FILTER (WHERE is_malicious = 1 AND malicious_scenario = 2)
                    AS scenario_2_users,
                COUNT(*) FILTER (WHERE is_malicious = 1 AND malicious_scenario = 3)
                    AS scenario_3_users
            FROM warehouse.dim_user
        """), conn)
    return stats.iloc[0].to_dict()


def main() -> int:
    logger.info("=" * 60)
    logger.info("FLAG MALICIOUS USERS IN dim_user")
    logger.info("=" * 60)

    malicious = load_r42_malicious()
    result = flag_users(malicious)

    print()
    print("=" * 60)
    print("MALICIOUS USER FLAGGING SUMMARY")
    print("=" * 60)
    print(f"  Users flagged:  {result['rows_updated']}")
    print(f"  Not found:      {len(result['not_found'])}")
    if result["not_found"]:
        print(f"  Missing IDs:    {result['not_found']}")

    stats = validate()
    print(f"\n  Total malicious users now in dim_user: {stats['malicious_users']}")
    print(f"    Scenario 1: {stats['scenario_1_users']}")
    print(f"    Scenario 2: {stats['scenario_2_users']}")
    print(f"    Scenario 3: {stats['scenario_3_users']}")
    print(f"  Legitimate users:                       {stats['legitimate_users']}")
    print("=" * 60)

    return 0 if not result["not_found"] else 0  # Always succeed; warn on missing


if __name__ == "__main__":
    sys.exit(main())