"""
User-level risk scoring.

Aggregates daily features into per-user risk profiles, then trains
a model to classify users as malicious vs legitimate.

This is the operational framing — SOCs investigate users, not days.
"""
import logging
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score,
    precision_recall_curve,
)
from sklearn.model_selection import train_test_split
from sqlalchemy import text

from src.warehouse import get_engine

warnings.filterwarnings("ignore", category=FutureWarning)
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------
# User-level feature aggregation
# ---------------------------------------------------------------------

def build_user_features() -> pd.DataFrame:
    """
    For each user, aggregate their post-baseline daily features into a
    single risk profile vector.

    Features capture both PEAK behavior (max values, indicating outlier days)
    and SUSTAINED behavior (mean values, indicating consistent patterns).
    """
    logger.info("Building user-level feature aggregations")
    engine = get_engine()

    with engine.begin() as conn:
        df = pd.read_sql(text("""
            WITH post_baseline AS (
                SELECT udml.*
                FROM warehouse.user_daily_ml_features udml
                JOIN warehouse.user_baselines ub ON ub.user_sk = udml.user_sk
                WHERE udml.feature_date >= ub.baseline_to
            )
            SELECT
                user_sk,
                -- PEAK signals (any single day that screamed)
                MAX(usb_ratio_personal) AS max_usb_ratio,
                MAX(usb_zscore_peer) AS max_usb_z,
                MAX(ext_emails_zscore_peer) AS max_ext_email_z,
                MAX(after_hours_zscore_peer) AS max_after_hours_z,
                MAX(multi_signal_count) AS max_signals_in_day,
                MAX(usb_connects) AS max_usb_in_day,
                MAX(ext_emails) AS max_ext_emails_in_day,
                MAX(file_accesses) AS max_files_in_day,

                -- SUSTAINED signals (averages across all post-baseline days)
                AVG(usb_ratio_personal) AS avg_usb_ratio,
                AVG(usb_zscore_peer) AS avg_usb_z,
                AVG(ext_emails_zscore_peer) AS avg_ext_email_z,
                AVG(after_hours_pct) AS avg_after_hours_pct,
                AVG(usb_dev_personal) AS avg_usb_dev,
                AVG(multi_signal_count::float) AS avg_signals_per_day,

                -- COUNT of "suspicious" days (multi_signal >= 2)
                SUM(CASE WHEN multi_signal_count >= 2 THEN 1 ELSE 0 END)
                    AS days_with_multi_signal,

                -- COUNT of "high deviation" days
                SUM(CASE WHEN usb_zscore_peer > 2 THEN 1 ELSE 0 END)
                    AS days_high_usb_z,
                SUM(CASE WHEN ext_emails_zscore_peer > 2 THEN 1 ELSE 0 END)
                    AS days_high_ext_email_z,

                -- Total activity counts
                COUNT(*) AS total_days_observed,
                SUM(usb_connects) AS lifetime_usb_total,
                SUM(ext_emails) AS lifetime_ext_emails_total,

                -- Labels
                MAX(is_malicious_user) AS is_malicious,
                MAX(malicious_scenario) AS malicious_scenario
            FROM post_baseline
            GROUP BY user_sk
        """), conn)

    # Replace NaN with 0 (users with no activity post-baseline)
    df = df.fillna(0)
    logger.info(f"  {len(df):,} users with features")
    logger.info(f"  Malicious: {df['is_malicious'].sum()}, "
                f"Legitimate: {(df['is_malicious'] == 0).sum()}")
    return df


# ---------------------------------------------------------------------
# Train/test split — by user, stratified by malicious flag
# ---------------------------------------------------------------------

FEATURE_COLS = [
    "max_usb_ratio", "max_usb_z", "max_ext_email_z", "max_after_hours_z",
    "max_signals_in_day", "max_usb_in_day", "max_ext_emails_in_day",
    "max_files_in_day",
    "avg_usb_ratio", "avg_usb_z", "avg_ext_email_z", "avg_after_hours_pct",
    "avg_usb_dev", "avg_signals_per_day",
    "days_with_multi_signal", "days_high_usb_z", "days_high_ext_email_z",
    "lifetime_usb_total", "lifetime_ext_emails_total",
]


def make_splits(df: pd.DataFrame, seed: int = 42):
    """30% test, 10% val, 60% train. Stratify by malicious."""
    train_val, test = train_test_split(
        df, test_size=0.3, random_state=seed, stratify=df["is_malicious"]
    )
    train, val = train_test_split(
        train_val, test_size=0.143, random_state=seed,
        stratify=train_val["is_malicious"],
    )
    logger.info(
        f"Splits: train={len(train)} (mal={train['is_malicious'].sum()}), "
        f"val={len(val)} (mal={val['is_malicious'].sum()}), "
        f"test={len(test)} (mal={test['is_malicious'].sum()})"
    )
    return train, val, test


# ---------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------

def train_rf(X, y) -> RandomForestClassifier:
    logger.info("Training user-level Random Forest")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    t0 = time.time()
    model.fit(X, y)
    logger.info(f"  Trained in {time.time()-t0:.1f}s")
    return model


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate(model, X, y, scenarios, label):
    y_proba = model.predict_proba(X)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, y_pred, average=None, zero_division=0
    )
    auc = roc_auc_score(y, y_proba)
    cm = confusion_matrix(y, y_pred)

    print(f"\n{'='*60}")
    print(f"{label} (default 0.5 threshold)")
    print(f"{'='*60}")
    print(f"  AUC:                  {auc:.4f}")
    print(f"  Malicious F1:         {f1[1]:.4f}")
    print(f"  Malicious Recall:     {recall[1]:.4f} ({cm[1][1]}/{cm[1].sum()})")
    print(f"  Malicious Precision:  {precision[1]:.4f}")
    print(f"  Legitimate Recall:    {recall[0]:.4f}")
    print(f"  Confusion Matrix:")
    print(f"    [[TN={cm[0][0]:4d}, FP={cm[0][1]:3d}],")
    print(f"     [FN={cm[1][0]:4d}, TP={cm[1][1]:3d}]]")

    print(f"\n  Per-scenario recall:")
    for scen in sorted(scenarios.unique()):
        if scen == 0:
            continue
        mask = (scenarios == scen) & (y == 1)
        caught = ((scenarios == scen) & (y == 1) & (y_pred == 1)).sum()
        total = mask.sum()
        if total > 0:
            print(f"    Scenario {int(scen)}: {caught}/{total} ({100*caught/total:.1f}%)")

    # Threshold sweep
    print(f"\n  Operating point tradeoffs:")
    precisions, recalls, thresholds = precision_recall_curve(y, y_proba)
    for target_prec in [0.50, 0.70, 0.90]:
        valid = np.where(precisions[:-1] >= target_prec)[0]
        if len(valid) == 0:
            print(f"    Precision≥{target_prec:.2f}: not achievable")
            continue
        best = valid[np.argmax(recalls[valid])]
        t = thresholds[best]
        y_p = (y_proba >= t).astype(int)
        tp = ((y_p == 1) & (y == 1)).sum()
        fp = ((y_p == 1) & (y == 0)).sum()
        print(f"    Precision≥{target_prec:.2f}: thresh={t:.3f}, "
              f"recall={recalls[best]:.3f}, TP={tp}, FP={fp}")

    return {"auc": auc, "f1": f1[1], "recall": recall[1], "precision": precision[1]}


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    logger.info("=" * 60)
    logger.info("USER-LEVEL RISK SCORING")
    logger.info("=" * 60)

    df = build_user_features()
    train, val, test = make_splits(df)

    X_train = train[FEATURE_COLS].values
    y_train = train["is_malicious"].values
    X_val = val[FEATURE_COLS].values
    y_val = val["is_malicious"].values
    X_test = test[FEATURE_COLS].values
    y_test = test["is_malicious"].values

    model = train_rf(X_train, y_train)

    evaluate(model, X_val, y_val, val["malicious_scenario"], "VALIDATION")
    test_metrics = evaluate(model, X_test, y_test, test["malicious_scenario"], "TEST")

    # Feature importance
    importances = pd.DataFrame({
        "feature": FEATURE_COLS,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)
    print(f"\n{'='*60}")
    print("TOP 15 FEATURES")
    print(f"{'='*60}")
    print(importances.head(15).to_string(index=False))

    # Save
    out_path = MODELS_DIR / "cert_user_rf_v1.joblib"
    joblib.dump({
        "model": model,
        "feature_names": FEATURE_COLS,
        "metadata": {
            "model_type": "RandomForest",
            "task": "user-level malicious classification",
            "n_estimators": 300,
            "max_depth": 10,
            "training_size": len(X_train),
            "test_auc": test_metrics["auc"],
            "test_f1": test_metrics["f1"],
            "test_recall": test_metrics["recall"],
            "test_precision": test_metrics["precision"],
        },
    }, out_path)
    logger.info(f"Saved {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())