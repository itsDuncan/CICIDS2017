"""
Phase 2 ML training — binary malicious user-day classifier + anomaly detector.

Trains:
    1. RandomForest binary classifier (in_attack_window vs not)
    2. Isolation Forest trained on legitimate-only

Usage:
    python -m src.cert.ml_train
"""
import logging
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score,
)

from src.cert.ml_features import NUMERIC_FEATURES, get_splits

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
# Training functions
# ---------------------------------------------------------------------

def train_rf(X_train, y_train) -> RandomForestClassifier:
    """Binary RF with class_weight='balanced' to handle imbalance."""
    logger.info(f"Training Random Forest (class_weight=balanced)")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    t0 = time.time()
    model.fit(X_train, y_train)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


def train_iforest(X_legitimate) -> IsolationForest:
    """Isolation Forest on legitimate-only data."""
    logger.info(f"Training Isolation Forest (legit-only baseline)")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,  # very strict — attack days are <1% of total
        n_jobs=-1,
        random_state=42,
    )
    t0 = time.time()
    model.fit(X_legitimate)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def find_optimal_threshold(model, X, y_true, label="VALIDATION"):
    """
    Find F1-optimal threshold and explore precision/recall tradeoff.

    Returns dict with threshold + metrics at that threshold.
    """
    from sklearn.metrics import f1_score, precision_recall_curve

    y_proba = model.predict_proba(X)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_proba)

    # Compute F1 at each threshold
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores[:-1])  # last element is recall=0 edge case
    best_threshold = thresholds[best_idx]

    print(f"\n{'='*60}")
    print(f"{label} — THRESHOLD ANALYSIS")
    print(f"{'='*60}")
    print(f"  Default threshold (0.5):")
    y_pred_05 = (y_proba >= 0.5).astype(int)
    f1_05 = f1_score(y_true, y_pred_05, zero_division=0)
    tp_05 = ((y_pred_05 == 1) & (y_true == 1)).sum()
    fp_05 = ((y_pred_05 == 1) & (y_true == 0)).sum()
    print(f"    F1={f1_05:.3f}, Precision={tp_05/(tp_05+fp_05+1e-9):.3f}, "
          f"Recall={tp_05/y_true.sum():.3f}, Alerts={(tp_05+fp_05)}")

    print(f"\n  F1-optimal threshold: {best_threshold:.4f}")
    y_pred_opt = (y_proba >= best_threshold).astype(int)
    tp_opt = ((y_pred_opt == 1) & (y_true == 1)).sum()
    fp_opt = ((y_pred_opt == 1) & (y_true == 0)).sum()
    print(f"    F1={f1_scores[best_idx]:.3f}, Precision={precisions[best_idx]:.3f}, "
          f"Recall={recalls[best_idx]:.3f}, Alerts={(tp_opt+fp_opt)}")

    # Show selected operating points along the PR curve
    print(f"\n  Operating point tradeoffs:")
    for target_precision in [0.30, 0.50, 0.70, 0.90]:
        valid_idx = np.where(precisions[:-1] >= target_precision)[0]
        if len(valid_idx) == 0:
            print(f"    Target precision {target_precision:.2f}: not achievable")
            continue
        best_at_target = valid_idx[np.argmax(recalls[valid_idx])]
        t = thresholds[best_at_target]
        y_p = (y_proba >= t).astype(int)
        tp = ((y_p == 1) & (y_true == 1)).sum()
        fp = ((y_p == 1) & (y_true == 0)).sum()
        print(f"    Precision≥{target_precision:.2f}: thresh={t:.3f}, "
              f"recall={recalls[best_at_target]:.3f}, "
              f"alerts={tp+fp} (TP={tp}, FP={fp})")

    return {"threshold": float(best_threshold), "f1": float(f1_scores[best_idx])}

def evaluate_binary(model, X, y_true, scenarios, label):
    """Per-scenario detection rates and overall metrics."""
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average=None, zero_division=0,
    )
    auc = roc_auc_score(y_true, y_proba)
    cm = confusion_matrix(y_true, y_pred)

    print(f"\n{'='*60}")
    print(f"{label} — RANDOM FOREST EVALUATION")
    print(f"{'='*60}")
    print(f"  AUC:                 {auc:.4f}")
    print(f"  Attack-day F1:       {f1[1]:.4f}")
    print(f"  Attack-day Recall:   {recall[1]:.4f}  ({cm[1][1]}/{cm[1].sum()})")
    print(f"  Attack-day Precision:{precision[1]:.4f}")
    print(f"  Benign Recall:       {recall[0]:.4f}")
    print(f"  False Positive Rate: {cm[0][1] / cm[0].sum() * 100:.3f}%")
    print(f"\n  Confusion Matrix:")
    print(f"    [[TN={cm[0][0]:6d}, FP={cm[0][1]:6d}],")
    print(f"     [FN={cm[1][0]:6d}, TP={cm[1][1]:6d}]]")

    # Per-scenario recall
    print(f"\n  Per-Scenario Detection (attack days only):")
    for scen in sorted(scenarios.unique()):
        if scen == 0:  # Not malicious — skip
            continue
        scen_mask = (scenarios == scen) & (y_true == 1)
        if scen_mask.sum() == 0:
            continue
        scen_caught = ((scenarios == scen) & (y_true == 1) & (y_pred == 1)).sum()
        scen_total = scen_mask.sum()
        print(f"    Scenario {scen}: {scen_caught}/{scen_total} "
              f"({100*scen_caught/scen_total:.1f}%)")
    return {"auc": auc, "f1": f1[1], "recall": recall[1], "precision": precision[1]}


def evaluate_iforest(model, X, y_true, scenarios, label):
    """Anomaly scores: more negative = more anomalous."""
    scores = -model.decision_function(X)  # negate so higher = more anomalous
    # Use top 1% as anomaly threshold (matches contamination rate)
    threshold = np.percentile(scores, 99)
    y_pred = (scores >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0,
    )
    auc = roc_auc_score(y_true, scores)

    print(f"\n{'='*60}")
    print(f"{label} — ISOLATION FOREST EVALUATION")
    print(f"{'='*60}")
    print(f"  AUC:                 {auc:.4f}")
    print(f"  Attack-day Recall:   {recall:.4f}")
    print(f"  Attack-day Precision:{precision:.4f}")
    print(f"  Attack-day F1:       {f1:.4f}")
    return {"auc": auc, "recall": recall, "precision": precision}


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    logger.info("=" * 60)
    logger.info("PHASE 2 ML TRAINING")
    logger.info("=" * 60)

    splits = get_splits()

    X_train = splits["train"][NUMERIC_FEATURES].values
    y_train = splits["train"]["in_attack_window"].values
    X_val = splits["val"][NUMERIC_FEATURES].values
    y_val = splits["val"]["in_attack_window"].values
    X_test = splits["test"][NUMERIC_FEATURES].values
    y_test = splits["test"]["in_attack_window"].values

    scen_val = splits["val"]["malicious_scenario"]
    scen_test = splits["test"]["malicious_scenario"]

    # ----- RF -----
    rf = train_rf(X_train, y_train)
    val_metrics = evaluate_binary(rf, X_val, y_val, scen_val, "VALIDATION (default 0.5)")
    test_metrics = evaluate_binary(rf, X_test, y_test, scen_test, "TEST (default 0.5)")

    # Threshold analysis on validation
    threshold_info = find_optimal_threshold(rf, X_val, y_val, "VALIDATION")
    optimal_threshold = threshold_info["threshold"]

    # Re-evaluate test set at the validation-derived optimal threshold
    print(f"\n{'='*60}")
    print(f"TEST EVALUATION @ optimal threshold ({optimal_threshold:.4f})")
    print(f"{'='*60}")
    y_test_proba = rf.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_proba >= optimal_threshold).astype(int)

    from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_test_pred, average=None, zero_division=0
    )
    cm = confusion_matrix(y_test, y_test_pred)

    print(f"  Attack-day F1:       {f1[1]:.4f}")
    print(f"  Attack-day Recall:   {recall[1]:.4f}  ({cm[1][1]}/{cm[1].sum()})")
    print(f"  Attack-day Precision:{precision[1]:.4f}")
    print(f"  False Positive Rate: {cm[0][1]/cm[0].sum()*100:.3f}%")

    # Per-scenario at optimal threshold
    print(f"\n  Per-scenario detection at optimal threshold:")
    for scen in sorted(scen_test.unique()):
        if scen == 0:
            continue
        scen_mask = (scen_test == scen) & (y_test == 1)
        if scen_mask.sum() == 0:
            continue
        scen_caught = ((scen_test == scen) & (y_test == 1) & (y_test_pred == 1)).sum()
        scen_total = scen_mask.sum()
        print(f"    Scenario {scen}: {scen_caught}/{scen_total} "
              f"({100*scen_caught/scen_total:.1f}%)")

    rf_path = MODELS_DIR / "cert_rf_v1.joblib"
    joblib.dump({
        "model": rf,
        "feature_names": NUMERIC_FEATURES,
        "optimal_threshold": optimal_threshold,
        "metadata": {
            "model_type": "RandomForest",
            "class_weight": "balanced",
            "n_estimators": 200,
            "max_depth": 15,
            "training_set_size": len(X_train),
            "val_auc": val_metrics["auc"],
            "test_auc": test_metrics["auc"],
            "test_recall_default": test_metrics["recall"],
            "test_precision_default": test_metrics["precision"],
            "optimal_threshold": float(optimal_threshold),
            "test_recall_optimal": float(recall[1]),
            "test_precision_optimal": float(precision[1]),
        },
    }, rf_path)
    logger.info(f"Saved {rf_path}")

    # ----- Feature importance -----
    importances = pd.DataFrame({
        "feature": NUMERIC_FEATURES,
        "importance": rf.feature_importances_,
    }).sort_values("importance", ascending=False)
    print(f"\n{'='*60}")
    print("TOP 15 FEATURES")
    print(f"{'='*60}")
    print(importances.head(15).to_string(index=False))

    # ----- Isolation Forest -----
    X_legit_train = splits["train"].loc[
        splits["train"]["in_attack_window"] == 0, NUMERIC_FEATURES
    ].values
    iforest = train_iforest(X_legit_train)
    evaluate_iforest(iforest, X_test, y_test, scen_test, "TEST")

    if_path = MODELS_DIR / "cert_iforest_v1.joblib"
    joblib.dump({
        "model": iforest,
        "feature_names": NUMERIC_FEATURES,
    }, if_path)
    logger.info(f"Saved {if_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())