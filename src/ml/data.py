"""
Data loading and train/test split utilities.

Loads labeled rows from warehouse.fact_security_event and produces stratified
splits. Handles unlabeled rows (is_attack IS NULL) appropriately.
"""
import logging
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.ml.features import LABEL_COLUMNS, NUMERIC_FEATURES, ID_COLUMNS
from src.warehouse import get_engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Data loading from warehouse
# ---------------------------------------------------------------------

def load_labeled_data(
    sample_per_family: Optional[int] = None,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Load labeled events from the warehouse for training.

    Args:
        sample_per_family: If set, randomly sample this many rows per attack_family.
                           For tiny families like Infiltration (36 rows) or Exploit (11),
                           we take all available. None means load everything.
        seed: random seed for reproducibility.

    Returns:
        DataFrame with feature columns + label columns + identifier columns.
    """
    engine = get_engine()

    feature_cols = ", ".join(f'"{c}"' for c in NUMERIC_FEATURES + ID_COLUMNS + LABEL_COLUMNS)

    if sample_per_family is None:
        query = f"""
            SELECT {feature_cols}
            FROM warehouse.fact_security_event
            WHERE is_attack IS NOT NULL
        """
    else:
        # Stratified sample: per-family limit; small families return everything
        query = f"""
            WITH ranked AS (
                SELECT {feature_cols},
                       ROW_NUMBER() OVER (
                           PARTITION BY attack_family_denorm
                           ORDER BY random()
                       ) AS rn
                FROM warehouse.fact_security_event
                WHERE is_attack IS NOT NULL
            )
            SELECT {feature_cols} FROM ranked
            WHERE rn <= {sample_per_family}
        """

    logger.info(
        f"Loading labeled events "
        f"({'all' if sample_per_family is None else f'≤{sample_per_family}/family'})"
    )
    df = pd.read_sql(query, engine)
    logger.info(f"Loaded {len(df):,} labeled rows")

    # Quick class summary
    dist = df["attack_family_denorm"].value_counts().to_dict()
    logger.info(f"Class distribution: {dist}")
    return df


# ---------------------------------------------------------------------
# Feature/label separation
# ---------------------------------------------------------------------

def split_features_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Separate a loaded DataFrame into X (features only) and y (labels + IDs).
    """
    available_features = [c for c in NUMERIC_FEATURES if c in df.columns]
    missing = set(NUMERIC_FEATURES) - set(df.columns)
    if missing:
        logger.warning(f"Missing feature columns: {sorted(missing)}")

    X = df[available_features].copy()
    y = df[[c for c in (LABEL_COLUMNS + ID_COLUMNS) if c in df.columns]].copy()
    return X, y


# ---------------------------------------------------------------------
# Handle NaN/inf in features
# ---------------------------------------------------------------------

def clean_features(X: pd.DataFrame) -> pd.DataFrame:
    """
    Tree models tolerate NaN but not infinity. Coerce inf → NaN → 0.

    Note: Filling NaN with 0 is acceptable for flow features (most NaNs come
    from short-duration flows with no inter-arrival time data, where 0 is
    semantically correct: "no spread because there's nothing to compare").
    """
    X = X.copy()
    # Replace inf with NaN, then NaN with 0
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X


# ---------------------------------------------------------------------
# Stratified train/val/test split
# ---------------------------------------------------------------------

def stratified_split(
    df: pd.DataFrame,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
    stratify_col: str = "attack_family_denorm",
) -> dict:
    """
    Split a DataFrame into train / val / test sets stratified by attack_family.

    Returns a dict with keys train/val/test each containing the corresponding rows.
    """
    # First split off the test set
    train_val, test = train_test_split(
        df,
        test_size=test_size,
        random_state=seed,
        stratify=df[stratify_col],
    )

    # Then split val out of train+val
    val_frac_of_remaining = val_size / (1 - test_size)
    train, val = train_test_split(
        train_val,
        test_size=val_frac_of_remaining,
        random_state=seed,
        stratify=train_val[stratify_col],
    )

    logger.info(
        f"Splits: train={len(train):,}, val={len(val):,}, test={len(test):,}"
    )
    return {"train": train, "val": val, "test": test}


# ---------------------------------------------------------------------
# One-shot helper: ready-to-use splits
# ---------------------------------------------------------------------

def get_train_val_test_splits(
    sample_per_family: int = 25_000,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> dict:
    """
    One-shot: load + clean + split.

    Returns dict:
        {
            'X_train': DataFrame, 'y_train': DataFrame,
            'X_val':   DataFrame, 'y_val':   DataFrame,
            'X_test':  DataFrame, 'y_test':  DataFrame,
        }
    """
    df = load_labeled_data(sample_per_family=sample_per_family, seed=seed)
    splits = stratified_split(df, test_size=test_size, val_size=val_size, seed=seed)

    out = {}
    for name in ("train", "val", "test"):
        X, y = split_features_labels(splits[name])
        X = clean_features(X)
        out[f"X_{name}"] = X
        out[f"y_{name}"] = y

    return out