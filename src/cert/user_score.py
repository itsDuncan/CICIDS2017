"""
Score all users with the trained Phase 2 model and persist results.

Output table: warehouse.user_risk_scores
"""
import logging
import sys
from io import StringIO
from pathlib import Path

import joblib
import pandas as pd
from sqlalchemy import text

from src.cert.user_risk import build_user_features, FEATURE_COLS
from src.warehouse import get_engine

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "cert_user_rf_v1.joblib"

# Operating threshold from Day 6 — chosen at ~76% recall, 1 FP
OPERATING_THRESHOLD = 0.315


def ensure_table_exists():
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS warehouse.user_risk_scores (
                user_sk            BIGINT PRIMARY KEY,
                risk_score         NUMERIC(5,4) NOT NULL,
                risk_label         VARCHAR(20) NOT NULL,
                model_version      VARCHAR(20) NOT NULL,
                scored_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                is_malicious_truth SMALLINT,
                malicious_scenario SMALLINT
            )
        """))
    logger.info("Table ensured: user_risk_scores")


def label_from_score(score: float) -> str:
    if score >= 0.50:
        return "high"
    elif score >= OPERATING_THRESHOLD:
        return "elevated"
    elif score >= 0.10:
        return "low"
    return "baseline"


def main():
    logger.info("=" * 60)
    logger.info("PHASE 2 — FULL USER SCORING")
    logger.info("=" * 60)

    ensure_table_exists()

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    logger.info(f"Loaded model: {MODEL_PATH.name}")

    df = build_user_features()
    X = df[FEATURE_COLS].values
    df["risk_score"] = model.predict_proba(X)[:, 1].round(4)
    df["risk_label"] = df["risk_score"].apply(label_from_score)
    df["model_version"] = "phase2-v1.0"

    out = df[[
        "user_sk", "risk_score", "risk_label", "model_version",
        "is_malicious", "malicious_scenario",
    ]].rename(columns={
        "is_malicious": "is_malicious_truth",
    })

    # COPY into warehouse
    engine = get_engine()
    raw_conn = engine.raw_connection()
    try:
        cur = raw_conn.cursor()
        cur.execute("TRUNCATE warehouse.user_risk_scores")
        buf = StringIO()
        out.to_csv(buf, index=False, header=False, na_rep="")
        buf.seek(0)
        cur.copy_expert(
            "COPY warehouse.user_risk_scores ("
            "user_sk, risk_score, risk_label, model_version, "
            "is_malicious_truth, malicious_scenario) "
            "FROM STDIN WITH CSV NULL ''",
            buf,
        )
        raw_conn.commit()
        cur.close()
    finally:
        raw_conn.close()

    # Summary
    print()
    print("=" * 60)
    print("FULL USER SCORING SUMMARY")
    print("=" * 60)
    print(f"  Users scored:  {len(out):,}")
    print(f"\n  Risk label distribution:")
    for label, count in out["risk_label"].value_counts().items():
        print(f"    {label:<10} {count:>4}")
    print(f"\n  Catch breakdown at threshold ≥ {OPERATING_THRESHOLD}:")
    flagged = out[out["risk_score"] >= OPERATING_THRESHOLD]
    print(f"    Flagged users:           {len(flagged):>4}")
    print(f"    Of which truly malicious: {flagged['is_malicious_truth'].sum():>4}")
    print(f"    Of which legitimate:     {(flagged['is_malicious_truth']==0).sum():>4}")
    total_malicious = out["is_malicious_truth"].sum()
    caught = flagged["is_malicious_truth"].sum()
    print(f"\n  Overall recall: {caught}/{total_malicious} = {100*caught/total_malicious:.1f}%")
    print(f"  Precision:      {caught}/{len(flagged)} = {100*caught/max(len(flagged),1):.1f}%")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())