"""
Isolation Forest anomaly detector — catches novel/unknown attacks.

Strategy:
    Train on benign-only data so the model learns "what normal looks like".
    Score test events: low scores = anomalous = candidate attacks.

This complements the supervised models:
    - Supervised models catch KNOWN attack patterns
    - Isolation Forest catches UNKNOWN deviations from normal

Output:
    anomaly_score in [0, 1]:
        0.0 = perfectly normal
        1.0 = extremely anomalous
"""
import logging
import time
import warnings
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------
# Model factory
# ---------------------------------------------------------------------

def make_isolation_forest(
    contamination: float = 0.05,
    n_estimators: int = 200,
    max_samples: str = "auto",
    n_jobs: int = -1,
    random_state: int = 42,
) -> IsolationForest:
    """
    Construct an Isolation Forest.

    Args:
        contamination: expected proportion of outliers (0.05 = 5%).
            Lower = stricter (only the most extreme are flagged).
        n_estimators: number of trees (more = more stable scores)
        max_samples: how many samples to draw for each tree

    Note: When training on benign-only data, contamination should be low
    because we don't expect benign data to contain many outliers.
    """
    return IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        max_samples=max_samples,
        n_jobs=n_jobs,
        random_state=random_state,
        verbose=0,
    )


# ---------------------------------------------------------------------
# Training (benign-only)
# ---------------------------------------------------------------------

def train_on_benign(X_train, y_train_str, contamination: float = 0.05) -> IsolationForest:
    """
    Fit Isolation Forest using only benign rows.

    Args:
        X_train: features
        y_train_str: attack_family_denorm series
        contamination: how strict to be — see make_isolation_forest

    Returns:
        Trained IsolationForest model.
    """
    benign_mask = y_train_str == "Benign"
    X_benign = X_train[benign_mask]

    logger.info(f"Training Isolation Forest on {len(X_benign):,} benign rows")
    logger.info(f"  Contamination: {contamination} (lower = stricter)")

    model = make_isolation_forest(contamination=contamination)
    t0 = time.time()
    model.fit(X_benign)
    logger.info(f"  Trained in {time.time() - t0:.1f}s")
    return model


# ---------------------------------------------------------------------
# Scoring — convert raw scores to 0-1 anomaly probability
# ---------------------------------------------------------------------

def score_anomaly(model: IsolationForest, X) -> np.ndarray:
    """
    Score samples. Returns array of anomaly scores in [0, 1].

    Raw IsolationForest scores:
        decision_function: positive = normal, negative = anomalous
        Range: roughly [-0.5, 0.5] but varies

    We normalize to [0, 1]:
        0.0 = most normal
        1.0 = most anomalous
    """
    raw_scores = model.decision_function(X)
    # Invert so higher = more anomalous, then normalize to [0, 1]
    anomaly = -raw_scores
    # Min-max normalize for interpretable scoring
    anomaly_normalized = (anomaly - anomaly.min()) / (anomaly.max() - anomaly.min() + 1e-10)
    return anomaly_normalized


def classify_anomaly(scores: np.ndarray, threshold: float = 0.5) -> np.ndarray:
    """Binary anomaly classification: 1 = anomaly, 0 = normal."""
    return (scores >= threshold).astype(int)


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate_separability(
    scores: np.ndarray,
    y_true_str: pd.Series,
    label: str = "Anomaly Detector"
) -> pd.DataFrame:
    """
    Show whether anomaly scores separate attacks from benign.

    For each class, report the distribution of anomaly scores.
    A good detector: benign has low scores, attacks have higher scores.
    """
    df = pd.DataFrame({
        "attack_family": y_true_str.values,
        "anomaly_score": scores,
    })
    summary = df.groupby("attack_family")["anomaly_score"].agg(
        ["count", "mean", "median", "std", "min", "max"]
    ).round(4)
    return summary


def detection_rate_at_threshold(
    scores: np.ndarray,
    y_true_str: pd.Series,
    threshold: float = 0.5,
) -> pd.DataFrame:
    """
    Per-class: how many events flagged as anomalous at given threshold?
    """
    is_anomaly = scores >= threshold
    rows = []
    for cls in y_true_str.unique():
        mask = y_true_str == cls
        n_total = mask.sum()
        n_flagged = (is_anomaly & mask).sum()
        pct = round(100 * n_flagged / max(n_total, 1), 2)
        rows.append({
            "class": cls,
            "n_total": int(n_total),
            "n_flagged": int(n_flagged),
            "detection_rate_pct": pct,
        })
    return pd.DataFrame(rows).sort_values("detection_rate_pct", ascending=False)


# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

def save_model(model, name: str = "iforest_v1", metadata: Optional[dict] = None) -> Path:
    """Persist Isolation Forest with metadata."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = {
        "model": model,
        "feature_names": list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else None,
        "metadata": metadata or {},
    }
    joblib.dump(bundle, path)
    logger.info(f"Model saved: {path}")
    return path


def load_model(name: str = "iforest_v1") -> dict:
    """Load Isolation Forest bundle."""
    path = MODELS_DIR / f"{name}.joblib"
    bundle = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return bundle