"""
Production scoring pipeline — score every event in fact_security_event.

Loads all three models, scores in chunks to manage memory, then UPDATEs
the warehouse with priority_score, priority_label, anomaly_score,
model_version, and scored_at.

Usage:
    python -m src.ml.score                 # full warehouse scoring
    python -m src.ml.score --limit 10000   # debug: score subset
    python -m src.ml.score --chunk-size 250000   # memory tuning
"""
import argparse
import logging
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import psycopg2
from sqlalchemy import text

from src.etl.logger import get_logger
from src.ml.evaluate import load_all_models
from src.ml.features import NUMERIC_FEATURES
from src.ml.priority import score_events
from src.warehouse import get_engine

warnings.filterwarnings("ignore", category=FutureWarning)

logger = get_logger("score")

# Model version tag written to fact_security_event.model_version
MODEL_VERSION = "phase1-v1.0"


# ---------------------------------------------------------------------
# Feature loading from warehouse
# ---------------------------------------------------------------------

def fetch_chunk(engine, offset: int, chunk_size: int) -> pd.DataFrame:
    """Read a chunk of fact_security_event with features + event_id for write-back."""
    feature_cols = ", ".join(f'"{c}"' for c in NUMERIC_FEATURES)
    query = f"""
        SELECT event_id, attack_family_denorm, {feature_cols}
        FROM warehouse.fact_security_event
        ORDER BY event_id
        OFFSET {offset}
        LIMIT {chunk_size}
    """
    return pd.read_sql(query, engine)


def total_fact_rows(engine) -> int:
    """Return the total row count in fact_security_event."""
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT COUNT(*) FROM warehouse.fact_security_event")
        ).scalar()


# ---------------------------------------------------------------------
# Score handling — clean NaN/inf same as training pipeline
# ---------------------------------------------------------------------

def clean_features(X: pd.DataFrame) -> pd.DataFrame:
    return X.replace([np.inf, -np.inf], np.nan).fillna(0)


# ---------------------------------------------------------------------
# Write-back via COPY → temp table → UPDATE join
# ---------------------------------------------------------------------

def upsert_chunk_scores(
    conn,
    chunk_results: pd.DataFrame,
    scored_at: datetime,
):
    """
    Write scoring results for a chunk via temp-table UPDATE pattern.

    This is much faster than row-by-row UPDATE for 100K+ rows.

    Strategy:
        1. CREATE TEMP TABLE matching score columns
        2. COPY chunk into temp table
        3. UPDATE fact_security_event FROM temp table by event_id
    """
    cur = conn.cursor()

    # 1. Create temp table
    cur.execute("""
        CREATE TEMP TABLE _score_chunk (
            event_id BIGINT,
            priority_score NUMERIC(5,4),
            priority_label VARCHAR(20),
            anomaly_score NUMERIC(5,4)
        ) ON COMMIT DROP
    """)

    # 2. COPY into temp
    from io import StringIO
    buf = StringIO()
    chunk_results[["event_id", "priority_score", "priority_label", "anomaly_score"]].to_csv(
        buf, index=False, header=False
    )
    buf.seek(0)
    cur.copy_expert(
        "COPY _score_chunk (event_id, priority_score, priority_label, anomaly_score) "
        "FROM STDIN WITH CSV",
        buf,
    )

    # 3. UPDATE join
    cur.execute("""
        UPDATE warehouse.fact_security_event AS f
        SET priority_score = s.priority_score,
            priority_label = s.priority_label,
            anomaly_score  = s.anomaly_score,
            model_version  = %s,
            scored_at      = %s
        FROM _score_chunk s
        WHERE f.event_id = s.event_id
    """, (MODEL_VERSION, scored_at))

    # 4. Drop temp explicitly (ON COMMIT DROP also fires)
    cur.execute("DROP TABLE _score_chunk")
    cur.close()


def get_psycopg2_conn():
    """Build a psycopg2 connection from the same .env credentials as SQLAlchemy."""
    import os
    import re
    from urllib.parse import unquote_plus
    from src.warehouse.db import get_database_url

    url = get_database_url()
    m = re.match(
        r"postgresql\+psycopg2://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)",
        url,
    )
    if not m:
        raise RuntimeError(f"Could not parse DATABASE_URL: {url}")
    user, password, host, port, dbname = m.groups()
    password = unquote_plus(password)

    return psycopg2.connect(
        host=host, port=port, dbname=dbname, user=user, password=password
    )


# ---------------------------------------------------------------------
# Main scoring loop
# ---------------------------------------------------------------------

def score_all(chunk_size: int = 100_000, limit: int = None) -> dict:
    """Score the full fact table in chunks, writing back to warehouse."""
    engine = get_engine()

    # Load all 3 models once
    bundles = load_all_models()
    rf_model = bundles["rf_binary_v1"]["model"]
    xgb_model = bundles["xgb_multiclass_v1"]["model"]
    xgb_le = bundles["xgb_multiclass_v1"]["label_encoder"]
    iforest_model = bundles["iforest_v1"]["model"]
    logger.info(f"Loaded all 3 models")

    # Discover total rows
    total = total_fact_rows(engine)
    if limit is not None:
        total = min(total, limit)
    logger.info(f"Scoring {total:,} rows in chunks of {chunk_size:,}")

    scored_at = datetime.now()
    processed = 0
    label_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    t0 = time.time()

    # Get psycopg2 connection for the UPDATEs
    pg_conn = get_psycopg2_conn()
    pg_conn.autocommit = False

    try:
        offset = 0
        while processed < total:
            this_chunk = min(chunk_size, total - processed)
            t_chunk = time.time()

            # Fetch
            chunk = fetch_chunk(engine, offset=offset, chunk_size=this_chunk)
            if len(chunk) == 0:
                break

            # Clean features
            X = clean_features(chunk[NUMERIC_FEATURES])
            attack_families = chunk["attack_family_denorm"].fillna("Benign")

            # Score
            scored = score_events(
                X=X,
                attack_families=attack_families,
                rf_model=rf_model,
                xgb_model=xgb_model,
                xgb_le=xgb_le,
                iforest_model=iforest_model,
            )
            scored["event_id"] = chunk["event_id"].values

            # Persist
            upsert_chunk_scores(pg_conn, scored, scored_at)
            pg_conn.commit()

            # Tally
            for lbl, count in scored["priority_label"].value_counts().to_dict().items():
                label_counts[lbl] = label_counts.get(lbl, 0) + int(count)

            processed += len(chunk)
            offset += len(chunk)
            elapsed = time.time() - t_chunk
            total_elapsed = time.time() - t0
            rate = processed / max(total_elapsed, 0.001)
            eta_sec = (total - processed) / max(rate, 0.001)

            logger.info(
                f"  Chunk {offset // chunk_size}: {processed:,}/{total:,} "
                f"({100 * processed / total:.1f}%) | "
                f"chunk time: {elapsed:.1f}s | rate: {rate:.0f}/s | "
                f"ETA: {eta_sec:.0f}s"
            )

    except Exception:
        pg_conn.rollback()
        raise
    finally:
        pg_conn.close()

    total_time = time.time() - t0
    logger.info(f"Scoring complete: {processed:,} rows in {total_time:.1f}s "
                f"({processed / max(total_time, 0.001):.0f} rows/sec)")

    return {
        "rows_scored": processed,
        "elapsed_seconds": round(total_time, 1),
        "label_distribution": label_counts,
        "model_version": MODEL_VERSION,
        "scored_at": scored_at.isoformat(),
    }


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="SOC Sentinel — score fact_security_event with ML priority"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=100_000,
        help="Number of rows per scoring chunk (default: 100000)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit total rows scored (default: all rows)",
    )
    return parser.parse_args(argv)


def print_summary(result: dict):
    print()
    print("=" * 60)
    print("SCORING RUN SUMMARY")
    print("=" * 60)
    print(f"  Model version:    {result['model_version']}")
    print(f"  Rows scored:      {result['rows_scored']:,}")
    print(f"  Duration:         {result['elapsed_seconds']}s")
    print(f"  Throughput:       {result['rows_scored'] / max(result['elapsed_seconds'], 0.001):.0f} rows/sec")
    print(f"\n  Priority labels:")
    total = result["rows_scored"]
    for label in ["critical", "high", "medium", "low", "info"]:
        count = result["label_distribution"].get(label, 0)
        pct = 100 * count / max(total, 1)
        print(f"    {label:<10} {count:>10,}  ({pct:5.2f}%)")
    print("=" * 60)


def main(argv=None) -> int:
    args = parse_args(argv)
    logger.info(f"Starting scoring: chunk_size={args.chunk_size}, limit={args.limit}")

    try:
        result = score_all(chunk_size=args.chunk_size, limit=args.limit)
        print_summary(result)
        return 0
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Scoring failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())