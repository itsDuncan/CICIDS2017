"""
XGBoost multi-class classifier — predicts attack family.

Predicts which of the 9 attack families a flow belongs to:
    Benign, DoS, DDoS, Brute Force, Reconnaissance, Web Attack,
    Botnet, Infiltration, Exploit

Trained with class weights to compensate for severe class imbalance
(Infiltration: 36 rows; Exploit: 11 rows).
"""
import logging
import time
import warnings
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

# Silence imbalanced-learn / xgboost FutureWarnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------
# Label encoding
# ---------------------------------------------------------------------

def fit_label_encoder(y_str: pd.Series) -> LabelEncoder:
    """Fit a LabelEncoder for attack families → integers."""
    le = LabelEncoder()
    le.fit(y_str)
    logger.info(f"Label encoding map:")
    for i, cls in enumerate(le.classes_):
        logger.info(f"  {i} → {cls}")
    return le


# ---------------------------------------------------------------------
# Per-class sample weights (handles imbalance natively)
# ---------------------------------------------------------------------

def compute_sample_weights(y_encoded: np.ndarray) -> np.ndarray:
    """
    Compute per-row weights inversely proportional to class frequency.

    This is XGBoost's equivalent of scikit-learn's class_weight='balanced'.
    Each row gets weight = total_samples / (n_classes * class_count).
    """
    from sklearn.utils.class_weight import compute_class_weight
    classes = np.unique(y_encoded)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_encoded)
    class_to_weight = dict(zip(classes, weights))
    sample_weights = np.array([class_to_weight[c] for c in y_encoded])

    logger.info("Class weights (higher = rarer class):")
    for c, w in class_to_weight.items():
        count = (y_encoded == c).sum()
        logger.info(f"  Class {c}: n={count:>6,}  weight={w:.4f}")
    return sample_weights


# ---------------------------------------------------------------------
# Model factory
# ---------------------------------------------------------------------

def make_xgboost(num_classes: int, seed: int = 42) -> xgb.XGBClassifier:
    """
    Construct an XGBoost classifier with sensible defaults for tabular data.

    Why these hyperparameters:
        - n_estimators=200: enough trees for convergence, not so many we overfit
        - max_depth=8: tree depth; deeper captures interactions but risks overfit
        - learning_rate=0.1: standard; lower needs more trees
        - tree_method='hist': histogram-based splits, fast on large data
        - eval_metric='mlogloss': appropriate for multi-class probability
    """
    return xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=num_classes,
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        tree_method="hist",
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=seed,
        verbosity=0,
    )


# ---------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------

def train(X_train, y_train_str, X_val, y_val_str):
    """
    Train XGBoost multi-class classifier with class-balanced weights.

    Returns:
        model: trained XGBClassifier
        label_encoder: fitted LabelEncoder for converting predictions back to strings
    """
    le = fit_label_encoder(y_train_str)
    y_train = le.transform(y_train_str)
    y_val = le.transform(y_val_str)

    sample_weights = compute_sample_weights(y_train)

    model = make_xgboost(num_classes=len(le.classes_))

    logger.info(f"Training XGBoost ({len(le.classes_)} classes, {len(X_train):,} rows)")
    t0 = time.time()
    model.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    logger.info(f"  Trained in {time.time() - t0:.1f}s")

    return model, le


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate(model, le: LabelEncoder, X, y_str, label: str = "model") -> dict:
    """Per-class and overall metrics for multi-class classifier."""
    y_true = le.transform(y_str)
    t0 = time.time()
    y_pred = model.predict(X)
    pred_time = time.time() - t0

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average=None, zero_division=0
    )

    overall_precision, overall_recall, overall_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )

    per_class = {
        le.classes_[i]: {
            "precision": round(precision[i], 4),
            "recall": round(recall[i], 4),
            "f1": round(f1[i], 4),
            "support": int(support[i]),
        }
        for i in range(len(le.classes_))
    }

    cm = confusion_matrix(y_true, y_pred)

    return {
        "label": label,
        "per_class": per_class,
        "macro_precision": round(overall_precision, 4),
        "macro_recall": round(overall_recall, 4),
        "macro_f1": round(overall_f1, 4),
        "accuracy": round((y_pred == y_true).mean(), 4),
        "confusion_matrix": cm.tolist(),
        "class_names": list(le.classes_),
        "n_samples": len(y_true),
        "pred_time_sec": round(pred_time, 2),
    }


def format_per_class_summary(metrics: dict) -> pd.DataFrame:
    """Tabular per-class metrics."""
    rows = []
    for cls, m in metrics["per_class"].items():
        rows.append({
            "Class": cls,
            "Support": m["support"],
            "Precision": m["precision"],
            "Recall": m["recall"],
            "F1": m["f1"],
        })
    df = pd.DataFrame(rows).sort_values("Support", ascending=False)
    return df


# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

def save_model(model, le: LabelEncoder, name: str = "xgb_multiclass_v1",
               metadata: Optional[dict] = None) -> Path:
    """Persist model + label encoder bundle."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = {
        "model": model,
        "label_encoder": le,
        "feature_names": list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else None,
        "metadata": metadata or {},
    }
    joblib.dump(bundle, path)
    logger.info(f"Model saved: {path}")
    return path


def load_model(name: str = "xgb_multiclass_v1") -> dict:
    """Load model bundle including label encoder."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return bundle