"""
Phase 2 ML feature definitions and data loading.

Reads user_daily_ml_features and produces train/val/test splits.
"""
import logging
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sqlalchemy import text

from src.warehouse import get_engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Feature column definitions
# ---------------------------------------------------------------------

# Raw daily counts
RAW_FEATURES = [
    "events_total", "usb_connects", "emails_sent", "ext_emails",
    "file_accesses", "logons", "after_hours_events", "weekend_events",
    "distinct_pcs",
]

# Personal-baseline deviations (raw and ratio)
PERSONAL_FEATURES = [
    "usb_dev_personal", "emails_dev_personal", "ext_emails_dev_personal",
    "files_dev_personal", "usb_ratio_personal", "ext_emails_ratio_personal",
]

# Peer-group z-scores
PEER_FEATURES = [
    "usb_zscore_peer", "ext_emails_zscore_peer", "after_hours_zscore_peer",
]

# Composite indicators
COMPOSITE_FEATURES = ["after_hours_pct", "multi_signal_count", "day_of_week"]

# All numeric features
NUMERIC_FEATURES = RAW_FEATURES + PERSONAL_FEATURES + PEER_FEATURES + COMPOSITE_FEATURES

# Label columns
LABEL_COLUMNS = ["in_attack_window", "is_malicious_user", "malicious_scenario"]

# ID columns (kept for joining back to warehouse)
ID_COLUMNS = ["user_sk", "feature_date"]


# ---------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------

def load_features() -> pd.DataFrame:
    """Load entire ML feature table."""
    engine = get_engine()
    cols = ", ".join(NUMERIC_FEATURES + LABEL_COLUMNS + ID_COLUMNS)
    with engine.begin() as conn:
        df = pd.read_sql(text(f"""
            SELECT {cols}
            FROM warehouse.user_daily_ml_features
        """), conn)

    # Replace inf and NaN with 0 (matches Phase 1 cleaning)
    df[NUMERIC_FEATURES] = df[NUMERIC_FEATURES].replace([np.inf, -np.inf], 0).fillna(0)
    logger.info(f"Loaded {len(df):,} feature rows")
    return df


def filter_post_baseline(df: pd.DataFrame, baseline_days: int = 60) -> pd.DataFrame:
    """
    Filter to user-days AFTER each user's baseline period.

    Baseline period: first 60 days of each user's activity.
    We exclude those days from training because malicious labels there
    are absorbed into baselines (especially Scenario 3).
    """
    engine = get_engine()
    with engine.begin() as conn:
        baselines = pd.read_sql(text("""
            SELECT user_sk, baseline_to
            FROM warehouse.user_baselines
        """), conn)
    baselines["baseline_to"] = pd.to_datetime(baselines["baseline_to"])
    df = df.merge(baselines, on="user_sk", how="left")
    df["feature_date"] = pd.to_datetime(df["feature_date"])
    pre = len(df)
    df = df[df["feature_date"] >= df["baseline_to"]].drop(columns="baseline_to")
    logger.info(f"Post-baseline filter: {pre:,} → {len(df):,} rows")
    return df


def stratified_split(
    df: pd.DataFrame,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> dict:
    """
    Split into train/val/test, stratified by in_attack_window so each set
    has the same malicious-day proportion.
    """
    train_val, test = train_test_split(
        df, test_size=test_size, random_state=seed,
        stratify=df["in_attack_window"],
    )
    val_frac = val_size / (1 - test_size)
    train, val = train_test_split(
        train_val, test_size=val_frac, random_state=seed,
        stratify=train_val["in_attack_window"],
    )
    logger.info(
        f"Splits: train={len(train):,}, val={len(val):,}, test={len(test):,}"
    )
    logger.info(
        f"  Attack days per split: "
        f"train={train['in_attack_window'].sum()}, "
        f"val={val['in_attack_window'].sum()}, "
        f"test={test['in_attack_window'].sum()}"
    )
    return {"train": train, "val": val, "test": test}


def get_splits(seed: int = 42) -> dict:
    """One-shot: load + filter + split."""
    df = load_features()
    df = filter_post_baseline(df)
    return stratified_split(df, seed=seed)