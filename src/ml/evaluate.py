"""
Unified model evaluation and comparison.

Evaluates all 3 models (Binary RF, Multi-class XGBoost, Isolation Forest)
on the same test set and produces comparison artifacts:

    - Side-by-side performance table
    - ROC and PR curves with thresholds annotated
    - Per-class detection rates
    - Recommended decision thresholds for production
"""
import logging
import warnings
from pathlib import Path
from typing import Optional

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score, confusion_matrix, f1_score,
    precision_recall_curve, roc_auc_score, roc_curve,
)

warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
FIGURES_DIR = Path(__file__).resolve().parents[2] / "docs" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------
# Load all models for comparison
# ---------------------------------------------------------------------

def load_all_models() -> dict:
    """Load all three trained models."""
    models = {}
    for name in ["rf_binary_v1", "xgb_multiclass_v1", "iforest_v1"]:
        path = MODELS_DIR / f"{name}.joblib"
        if path.exists():
            bundle = joblib.load(path)
            models[name] = bundle
            logger.info(f"Loaded {name}")
        else:
            logger.warning(f"Missing model: {path}")
    return models


# ---------------------------------------------------------------------
# Binary scoring helpers
# ---------------------------------------------------------------------

def binary_score_rf(model, X) -> np.ndarray:
    """Return P(attack=1) from Random Forest."""
    return model.predict_proba(X)[:, 1]


def binary_score_xgb(model, le, X) -> np.ndarray:
    """Return P(attack=1) from XGBoost = 1 - P(Benign)."""
    proba = model.predict_proba(X)
    benign_idx = list(le.classes_).index("Benign")
    return 1.0 - proba[:, benign_idx]


def binary_score_iforest(model, X) -> np.ndarray:
    """Normalized anomaly score in [0, 1]."""
    raw = -model.decision_function(X)
    return (raw - raw.min()) / (raw.max() - raw.min() + 1e-10)


# ---------------------------------------------------------------------
# ROC curve comparison
# ---------------------------------------------------------------------

def plot_roc_comparison(
    y_true: np.ndarray,
    scores_dict: dict,
    title: str = "ROC Curve — Model Comparison",
    save_path: Optional[Path] = None,
):
    """Overlay ROC curves for multiple models."""
    fig, ax = plt.subplots(figsize=(8, 7))

    for label, scores in scores_dict.items():
        fpr, tpr, _ = roc_curve(y_true, scores)
        auc = roc_auc_score(y_true, scores)
        ax.plot(fpr, tpr, label=f"{label} (AUC={auc:.4f})", linewidth=2)

    ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="Random (AUC=0.5)")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(title)
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
        logger.info(f"Saved ROC plot: {save_path}")
    plt.show()


def plot_pr_comparison(
    y_true: np.ndarray,
    scores_dict: dict,
    title: str = "Precision-Recall Curve — Model Comparison",
    save_path: Optional[Path] = None,
):
    """Overlay PR curves — more informative than ROC for imbalanced data."""
    fig, ax = plt.subplots(figsize=(8, 7))

    for label, scores in scores_dict.items():
        precision, recall, _ = precision_recall_curve(y_true, scores)
        ap = average_precision_score(y_true, scores)
        ax.plot(recall, precision, label=f"{label} (AP={ap:.4f})", linewidth=2)

    # Baseline = positive class prevalence
    baseline = y_true.mean()
    ax.axhline(baseline, linestyle="--", color="k", alpha=0.4,
               label=f"Baseline ({baseline:.2f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title(title)
    ax.legend(loc="lower left")
    ax.grid(alpha=0.3)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
        logger.info(f"Saved PR plot: {save_path}")
    plt.show()


# ---------------------------------------------------------------------
# Threshold tuning — find F1-optimal threshold per model
# ---------------------------------------------------------------------

def find_optimal_threshold(y_true: np.ndarray, scores: np.ndarray) -> dict:
    """Find threshold that maximizes F1 score for binary classification."""
    thresholds = np.linspace(0.01, 0.99, 99)
    best_f1 = 0
    best_threshold = 0.5
    best_precision = 0
    best_recall = 0

    for t in thresholds:
        y_pred = (scores >= t).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = t
            tp = ((y_pred == 1) & (y_true == 1)).sum()
            fp = ((y_pred == 1) & (y_true == 0)).sum()
            fn = ((y_pred == 0) & (y_true == 1)).sum()
            best_precision = tp / max(tp + fp, 1)
            best_recall = tp / max(tp + fn, 1)

    return {
        "threshold": round(best_threshold, 3),
        "f1": round(best_f1, 4),
        "precision": round(best_precision, 4),
        "recall": round(best_recall, 4),
    }


# ---------------------------------------------------------------------
# Per-class detection comparison across all 3 models
# ---------------------------------------------------------------------

def per_class_detection_comparison(
    y_true_str: pd.Series,
    binary_scores_dict: dict,
    threshold: float = 0.5,
) -> pd.DataFrame:
    """
    For each attack family, compare detection rates across all 3 models.
    Shows which model catches which attack type best.
    """
    rows = []
    for cls in sorted(y_true_str.unique()):
        mask = y_true_str == cls
        row = {"class": cls, "n_total": int(mask.sum())}
        for model_label, scores in binary_scores_dict.items():
            flagged = ((scores >= threshold) & mask).sum()
            row[f"{model_label}_detected"] = int(flagged)
            row[f"{model_label}_pct"] = round(100 * flagged / max(mask.sum(), 1), 1)
        rows.append(row)
    return pd.DataFrame(rows).sort_values("n_total", ascending=False)


# ---------------------------------------------------------------------
# Headline summary
# ---------------------------------------------------------------------

def summarize_models(
    y_true: np.ndarray,
    scores_dict: dict,
) -> pd.DataFrame:
    """Build a comparison table: each model's AUC, AP, optimal F1/threshold."""
    rows = []
    for label, scores in scores_dict.items():
        auc = roc_auc_score(y_true, scores)
        ap = average_precision_score(y_true, scores)
        optimal = find_optimal_threshold(y_true, scores)
        rows.append({
            "Model": label,
            "AUC": round(auc, 4),
            "Avg Precision": round(ap, 4),
            "Optimal Threshold": optimal["threshold"],
            "Optimal F1": optimal["f1"],
            "@Opt Precision": optimal["precision"],
            "@Opt Recall": optimal["recall"],
        })
    return pd.DataFrame(rows)