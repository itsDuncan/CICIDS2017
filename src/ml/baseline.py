"""
Random Forest binary classifier — baseline model for attack detection.

Three variants compared:
    1. Vanilla RF (no imbalance handling)
    2. Class-weighted RF (built-in scikit-learn balancing)
    3. SMOTE + RF (oversampled training data)

Best model persisted to models/rf_binary_v1.joblib for reuse.
"""
import logging
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_fscore_support,
)

logger = logging.getLogger(__name__)

# Models directory (gitignored)
MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------
# Model factory
# ---------------------------------------------------------------------

def make_random_forest(
    class_weight: Optional[str] = None,
    n_estimators: int = 100,
    max_depth: Optional[int] = 20,
    n_jobs: int = -1,
    random_state: int = 42,
) -> RandomForestClassifier:
    """
    Construct a Random Forest with sensible defaults for tabular SOC data.

    Args:
        class_weight: 'balanced' or None
        n_estimators: number of trees (100 is fast, 500 is more accurate)
        max_depth: tree depth limit (None = unlimited, 20 is a sane default)
        n_jobs: -1 uses all CPU cores
    """
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight=class_weight,
        n_jobs=n_jobs,
        random_state=random_state,
        verbose=0,
    )


# ---------------------------------------------------------------------
# Training utilities
# ---------------------------------------------------------------------

def train_vanilla(X_train, y_train) -> RandomForestClassifier:
    """Train RF with no imbalance handling."""
    logger.info("Training vanilla Random Forest (no imbalance handling)")
    model = make_random_forest(class_weight=None)
    t0 = time.time()
    model.fit(X_train, y_train)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


def train_weighted(X_train, y_train) -> RandomForestClassifier:
    """Train RF with class_weight='balanced'."""
    logger.info("Training Random Forest with class_weight='balanced'")
    model = make_random_forest(class_weight="balanced")
    t0 = time.time()
    model.fit(X_train, y_train)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


def train_with_smote(X_train, y_train, seed: int = 42) -> RandomForestClassifier:
    """Apply SMOTE oversampling to minority class, then train RF."""
    logger.info("Applying SMOTE oversampling")
    smote = SMOTE(random_state=seed, n_jobs=-1)
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
    logger.info(
        f"  Original train size: {len(y_train):,} "
        f"({(y_train == 1).sum():,} attacks, {(y_train == 0).sum():,} benign)"
    )
    logger.info(
        f"  After SMOTE:         {len(y_resampled):,} "
        f"({(y_resampled == 1).sum():,} attacks, {(y_resampled == 0).sum():,} benign)"
    )

    logger.info("Training Random Forest on SMOTE-resampled data")
    model = make_random_forest(class_weight=None)
    t0 = time.time()
    model.fit(X_resampled, y_resampled)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate(model, X, y_true, label: str = "model") -> dict:
    """
    Return a comprehensive evaluation dict for a binary classifier.

    Reports per-class precision/recall/F1, overall accuracy, AUC, and confusion matrix.
    """
    t0 = time.time()
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]
    pred_time = time.time() - t0

    # Per-class metrics
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average=None
    )
    auc = roc_auc_score(y_true, y_proba)
    cm = confusion_matrix(y_true, y_pred)

    return {
        "label": label,
        "auc": round(auc, 4),
        "accuracy": round((y_pred == y_true).mean(), 4),
        "benign_precision": round(precision[0], 4),
        "benign_recall": round(recall[0], 4),
        "benign_f1": round(f1[0], 4),
        "attack_precision": round(precision[1], 4),
        "attack_recall": round(recall[1], 4),
        "attack_f1": round(f1[1], 4),
        "confusion_matrix": cm.tolist(),  # [[TN, FP], [FN, TP]]
        "n_samples": len(y_true),
        "pred_time_sec": round(pred_time, 2),
    }


def format_metrics_summary(metrics: list[dict]) -> pd.DataFrame:
    """Side-by-side comparison of multiple model evaluations."""
    return pd.DataFrame([
        {
            "Model": m["label"],
            "AUC": m["auc"],
            "Accuracy": m["accuracy"],
            "Attack Precision": m["attack_precision"],
            "Attack Recall": m["attack_recall"],
            "Attack F1": m["attack_f1"],
            "Benign Recall": m["benign_recall"],
        }
        for m in metrics
    ])


# ---------------------------------------------------------------------
# Model persistence
# ---------------------------------------------------------------------

def save_model(model, name: str = "rf_binary_v1", metadata: Optional[dict] = None) -> Path:
    """Persist trained model with metadata."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = {
        "model": model,
        "feature_names": list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else None,
        "metadata": metadata or {},
    }
    joblib.dump(bundle, path)
    logger.info(f"Model saved: {path}")
    return path


def load_model(name: str = "rf_binary_v1") -> dict:
    """Load a persisted model bundle."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return bundle