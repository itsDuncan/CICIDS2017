"""
Priority score fusion — combines supervised + anomaly + severity signals.

Output:
    priority_score in [0, 1] — sortable priority for SOC dashboard
    priority_label in {critical, high, medium, low, info}

Components:
    1. supervised_score: max(RF P(attack), XGBoost P(attack)) — known threats
    2. anomaly_score:    Isolation Forest normalized — unknown/rare threats
    3. severity_weight:  from dim_attack_type.severity — domain knowledge
"""
import logging
import warnings
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

# Family → severity level mapping (mirrors dim_attack_type seed data)
# Used to convert XGBoost's predicted family string into a severity weight
FAMILY_TO_SEVERITY = {
    "Benign":          "info",
    "Botnet":          "high",
    "Brute Force":     "medium",
    "DDoS":            "critical",
    "DoS":             "high",
    "Exploit":         "critical",
    "Infiltration":    "critical",
    "Reconnaissance":  "low",
    "Web Attack":      "medium",
    "Unlabeled":       "info",
}

# Default fusion weights — sum to 1.0
DEFAULT_WEIGHTS = {
    "supervised": 0.65,   # increased — primary signal
    "anomaly":    0.15,   # decreased — safety net only
    "severity":   0.20,   # decreased — important but not dominant
}

# Severity → numeric weight (boosts inherently dangerous attacks)
SEVERITY_WEIGHTS = {
    "critical": 1.00,
    "high":     0.70,
    "medium":   0.40,
    "low":      0.20,
    "info":     0.00,
}

# Priority label thresholds — tuned to actual fused score distribution
PRIORITY_THRESHOLDS = [
    (0.75, "critical"),
    (0.55, "high"),
    (0.35, "medium"),
    (0.15, "low"),
    (0.00, "info"),
]

def fuse_priority_score(
    rf_proba: np.ndarray,
    xgb_attack_proba: np.ndarray,
    iforest_anomaly: np.ndarray,
    severity_weights: np.ndarray,
    weights: dict = None,
) -> np.ndarray:
    """
    Combine all signals into final priority_score in [0, 1].

    Includes a certainty bonus when both supervised models agree with
    high confidence — this elevates true-positive attacks that have
    lower-severity classifications (Brute Force, Reconnaissance).
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    sup = supervised_score(rf_proba, xgb_attack_proba)

    base = (
        weights["supervised"] * sup
        + weights["anomaly"] * iforest_anomaly
        + weights["severity"] * severity_weights
    )

    # Certainty bonus: both models very confident → boost score
    # Triggers when min(RF, XGB) > 0.95 — strict bilateral agreement
    both_confident = np.minimum(rf_proba, xgb_attack_proba)
    certainty_bonus = np.where(both_confident > 0.95, 0.10, 0.0)

    return np.clip(base + certainty_bonus, 0.0, 1.0)


# ---------------------------------------------------------------------
# Score fusion
# ---------------------------------------------------------------------

def supervised_score(rf_proba: np.ndarray, xgb_attack_proba: np.ndarray) -> np.ndarray:
    """
    Combine RF and XGBoost into one supervised confidence score.

    Uses max() rather than mean: if either model is highly confident,
    we trust that signal. This is the "any model says attack" interpretation.
    """
    return np.maximum(rf_proba, xgb_attack_proba)


def severity_weight_lookup(attack_families: pd.Series, severity_map: dict) -> np.ndarray:
    """
    Map attack_family_denorm strings to their numeric severity weights.

    Returns 0.0 for Benign/Unlabeled/missing.
    """
    return attack_families.map(severity_map).fillna(0.0).values


def fuse_priority_score(
    rf_proba: np.ndarray,
    xgb_attack_proba: np.ndarray,
    iforest_anomaly: np.ndarray,
    severity_weights: np.ndarray,
    weights: dict = None,
) -> np.ndarray:
    """
    Combine all signals into final priority_score in [0, 1].

    Args:
        rf_proba: Random Forest P(attack)
        xgb_attack_proba: XGBoost 1 - P(Benign)
        iforest_anomaly: normalized anomaly score
        severity_weights: per-row severity from attack family
        weights: optional override of DEFAULT_WEIGHTS

    Returns:
        Array of priority scores in [0, 1]
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    sup = supervised_score(rf_proba, xgb_attack_proba)
    return np.clip(
        weights["supervised"] * sup
        + weights["anomaly"] * iforest_anomaly
        + weights["severity"] * severity_weights,
        0.0,
        1.0,
    )


def assign_priority_label(scores: np.ndarray) -> np.ndarray:
    """Bucket continuous priority scores into label strings."""
    labels = np.empty(len(scores), dtype=object)
    for threshold, label in PRIORITY_THRESHOLDS:
        mask = (scores >= threshold) & (labels == None)
        labels[mask] = label
    # Any remaining null → info
    labels[labels == None] = "info"
    return labels


# ---------------------------------------------------------------------
# All-in-one: produce ready-to-load priority results
# ---------------------------------------------------------------------

def score_events(
    X: pd.DataFrame,
    attack_families: pd.Series,
    rf_model,
    xgb_model,
    xgb_le,
    iforest_model,
    weights: dict = None,
) -> pd.DataFrame:
    """
    Run all three models on X and produce ready-to-write priority records.

    Returns DataFrame with columns:
        rf_attack_proba       — Binary RF P(attack)
        xgb_attack_proba      — XGBoost 1 - P(Benign)
        xgb_predicted_family  — XGBoost's predicted attack family
        anomaly_score         — Isolation Forest normalized score
        priority_score        — fused score in [0, 1]
        priority_label        — critical/high/medium/low/info
    """
    logger.info(f"Scoring {len(X):,} events through all 3 models")

    # Random Forest binary score
    rf_proba = rf_model.predict_proba(X)[:, 1]

    # XGBoost multi-class — gather all probabilities, derive attack prob and family
    xgb_proba = xgb_model.predict_proba(X)
    benign_idx = list(xgb_le.classes_).index("Benign")
    xgb_attack_proba = 1.0 - xgb_proba[:, benign_idx]
    xgb_predicted_class = xgb_proba.argmax(axis=1)
    xgb_predicted_family = xgb_le.inverse_transform(xgb_predicted_class)

    # Isolation Forest anomaly score (normalize same way as before)
    iforest_raw = -iforest_model.decision_function(X)
    iforest_norm = (iforest_raw - iforest_raw.min()) / (iforest_raw.max() - iforest_raw.min() + 1e-10)

    # Severity weights from XGBoost's predicted family (we'll use predicted, not actual,
    # because at inference time we don't know the real label)
    predicted_family_series = pd.Series(xgb_predicted_family)
    severity_strings = predicted_family_series.map(FAMILY_TO_SEVERITY).fillna("info")
    severity_array = severity_strings.map(SEVERITY_WEIGHTS).fillna(0.0).values

    # Fuse
    priority_scores = fuse_priority_score(
        rf_proba=rf_proba,
        xgb_attack_proba=xgb_attack_proba,
        iforest_anomaly=iforest_norm,
        severity_weights=severity_array,
        weights=weights,
    )
    priority_labels = assign_priority_label(priority_scores)

    return pd.DataFrame({
        "rf_attack_proba": rf_proba,
        "xgb_attack_proba": xgb_attack_proba,
        "xgb_predicted_family": xgb_predicted_family,
        "anomaly_score": iforest_norm,
        "priority_score": priority_scores,
        "priority_label": priority_labels,
    })