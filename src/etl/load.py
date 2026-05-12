"""
Load stage — write enriched DataFrame to PostgreSQL warehouse.

Responsibilities:
1. Resolve surrogate keys against seeded/grown dimensions
2. UPSERT new dim_asset rows (with geo + reputation enrichment)
3. UPSERT observed dim_port rows
4. Bulk COPY transformed/enriched data into fact_security_event

Idempotent in full-reload mode: TRUNCATEs fact table before load.
"""
import csv
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

import pandas as pd
import psycopg2
from sqlalchemy import text

from src.etl.context import PipelineContext
from src.etl.logger import get_logger
from src.warehouse import get_engine

logger = get_logger("load")


# ---------------------------------------------------------------------
# Temp directory for COPY operations
# ---------------------------------------------------------------------

def _get_temp_dir() -> Path:
    """Use C:\\temp on Windows for COPY temp files (avoids OneDrive)."""
    if os.name == "nt":
        temp_dir = Path(r"C:\temp\soc_sentinel")
    else:
        temp_dir = Path(tempfile.gettempdir()) / "soc_sentinel"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


# ---------------------------------------------------------------------
# STEP 1: Resolve dim_asset
# ---------------------------------------------------------------------

def upsert_dim_asset(df: pd.DataFrame, enriched: dict) -> dict[str, int]:
    """
    Ensure all IPs in df exist in dim_asset (with enrichment for external IPs).
    Returns mapping: {ip_address: asset_sk}.
    """
    # Build set of distinct IPs with their classification
    src_ips = df[["src_ip", "src_ip_class"]].rename(
        columns={"src_ip": "ip", "src_ip_class": "ip_class"}
    )
    dest_ips = df[["dest_ip", "dest_ip_class"]].rename(
        columns={"dest_ip": "ip", "dest_ip_class": "ip_class"}
    )
    all_ips = pd.concat([src_ips, dest_ips]).drop_duplicates(subset=["ip"])
    all_ips = all_ips[all_ips["ip"].notna()].copy()

    logger.info(f"Resolving {len(all_ips):,} distinct IPs against dim_asset")

    engine = get_engine()

    # Fetch existing IPs from dim_asset to avoid redundant inserts
    with engine.begin() as conn:
        existing = pd.read_sql(
            "SELECT asset_identifier, asset_sk FROM warehouse.dim_asset",
            conn,
        )
    existing_map = dict(zip(existing["asset_identifier"], existing["asset_sk"]))
    logger.info(f"  Found {len(existing_map):,} existing dim_asset rows")

    # Find new IPs needing insertion
    new_ips = all_ips[~all_ips["ip"].isin(existing_map)].copy()
    logger.info(f"  Need to INSERT {len(new_ips):,} new dim_asset rows")

    if len(new_ips) > 0:
        # Build INSERT records with enrichment merged in
        records = []
        for _, row in new_ips.iterrows():
            ip = row["ip"]
            ip_class = row["ip_class"]
            enrich_data = enriched.get(ip, {})

            records.append({
                "asset_identifier": ip,
                "asset_type": "host",
                "ip_address": ip,
                "is_internal": 1 if ip_class == "internal" else 0,
                "country_iso": enrich_data.get("country_iso"),
                "country_name": enrich_data.get("country_name"),
                "city": enrich_data.get("city"),
                "latitude": enrich_data.get("latitude"),
                "longitude": enrich_data.get("longitude"),
                "asn": enrich_data.get("asn"),
                "asn_org": enrich_data.get("asn_org"),
                "abuse_confidence": enrich_data.get("abuse_confidence"),
                "is_known_attacker": enrich_data.get("is_known_attacker", 0),
                "source_system": "CICIDS",
            })

        # Bulk INSERT
        insert_df = pd.DataFrame(records)
        insert_df.to_sql(
            "dim_asset",
            engine,
            schema="warehouse",
            if_exists="append",
            index=False,
            chunksize=1000,
            method="multi",
        )
        logger.info(f"  Inserted {len(insert_df):,} new dim_asset rows")

        # Re-fetch to get the new asset_sk values
        with engine.begin() as conn:
            updated = pd.read_sql(
                "SELECT asset_identifier, asset_sk FROM warehouse.dim_asset",
                conn,
            )
        existing_map = dict(zip(updated["asset_identifier"], updated["asset_sk"]))

    return existing_map


# ---------------------------------------------------------------------
# STEP 2: Resolve dim_port
# ---------------------------------------------------------------------

def upsert_dim_port(df: pd.DataFrame) -> dict[int, int]:
    """
    Ensure all observed ports exist in dim_port.
    Returns mapping: {port_number: port_sk}.
    """
    ports = pd.concat([df["src_port"], df["dest_port"]]).dropna().astype("int32").unique()
    logger.info(f"Resolving {len(ports):,} distinct ports against dim_port")

    engine = get_engine()

    # Fetch existing ports
    with engine.begin() as conn:
        existing = pd.read_sql(
            "SELECT port_number, port_sk FROM warehouse.dim_port",
            conn,
        )
    existing_map = dict(zip(existing["port_number"].astype("int32"), existing["port_sk"]))
    logger.info(f"  Found {len(existing_map):,} existing dim_port rows")

    # Find new ports
    new_ports = [p for p in ports if int(p) not in existing_map]
    logger.info(f"  Need to INSERT {len(new_ports):,} new dim_port rows")

    if new_ports:
        records = [{
            "port_number": int(p),
            "service_name": None,
            "port_category": "observed",
            "is_well_known": 1 if int(p) < 1024 else 0,
            "description": "Auto-added by ETL (observed in CICIDS data)",
        } for p in new_ports]

        insert_df = pd.DataFrame(records)
        insert_df.to_sql(
            "dim_port",
            engine,
            schema="warehouse",
            if_exists="append",
            index=False,
            chunksize=500,
            method="multi",
        )
        logger.info(f"  Inserted {len(insert_df):,} new dim_port rows")

        # Refetch
        with engine.begin() as conn:
            updated = pd.read_sql(
                "SELECT port_number, port_sk FROM warehouse.dim_port",
                conn,
            )
        existing_map = dict(zip(updated["port_number"].astype("int32"), updated["port_sk"]))

    return existing_map


# ---------------------------------------------------------------------
# STEP 3: Resolve other dimension FKs (read-only)
# ---------------------------------------------------------------------

def build_attack_type_map() -> dict[str, int]:
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(
            "SELECT attack_label, attack_sk FROM warehouse.dim_attack_type",
            conn,
        )
    return dict(zip(df["attack_label"], df["attack_sk"]))


def build_protocol_map() -> dict[int, int]:
    engine = get_engine()
    with engine.begin() as conn:
        df = pd.read_sql(
            "SELECT protocol_num, protocol_sk FROM warehouse.dim_protocol",
            conn,
        )
    return dict(zip(df["protocol_num"].astype("int16"), df["protocol_sk"]))


# ---------------------------------------------------------------------
# STEP 4: Apply mappings to the DataFrame
# ---------------------------------------------------------------------

# Columns expected in the final fact_security_event table (in order).
# Must match the DDL exactly.
FACT_COLUMNS = [
    "source_system", "date_sk", "time_sk",
    "src_asset_sk", "dest_asset_sk",
    "src_port_sk", "dest_port_sk",
    "protocol_sk", "attack_sk",
    "event_time", "flow_id",
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_variance",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "fwd_header_length", "bwd_header_length",
    "fwd_pkts_per_sec", "bwd_pkts_per_sec",
    "down_up_ratio", "avg_pkt_size", "avg_fwd_seg_size", "avg_bwd_seg_size",
    "fwd_avg_bytes_bulk", "fwd_avg_pkts_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk", "bwd_avg_pkts_bulk", "bwd_avg_bulk_rate",
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts", "subflow_bwd_bytes",
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "act_data_pkt_fwd", "min_seg_size_fwd",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "is_attack", "attack_family_denorm",
]

# Integer columns that PostgreSQL stores as BIGINT/INT/SMALLINT.
# Pandas converts these to float64 when NULLs exist; we must coerce back to
# nullable integer dtype so the CSV writer doesn't emit "1234.0" trailing zeros.
INT_COLUMNS = [
    # Surrogate keys (already populated by mappings — should be clean but coerce defensively)
    "date_sk", "time_sk",
    "src_asset_sk", "dest_asset_sk",
    "src_port_sk", "dest_port_sk",
    "protocol_sk", "attack_sk",
    # Volumetric counters
    "flow_duration",
    "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd",
    "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_max", "bwd_pkt_len_min",
    "pkt_len_min", "pkt_len_max",
    # IAT max/min/total (microseconds — bigint in DDL)
    "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_max", "bwd_iat_min",
    # Flag counts (smallint)
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    # Headers
    "fwd_header_length", "bwd_header_length",
    "down_up_ratio",
    # Bulk
    "fwd_avg_bytes_bulk", "fwd_avg_pkts_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk", "bwd_avg_pkts_bulk", "bwd_avg_bulk_rate",
    # Subflow
    "subflow_fwd_pkts", "subflow_fwd_bytes",
    "subflow_bwd_pkts", "subflow_bwd_bytes",
    # Window
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "act_data_pkt_fwd", "min_seg_size_fwd",
    # Active/idle max/min (bigint)
    "active_max", "active_min",
    "idle_max", "idle_min",
    # Labels
    "is_attack",
]


def coerce_integer_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Coerce integer columns from float64 to pandas nullable Int64.
    
    Why: pandas auto-promotes int columns to float when NaN is present,
    causing to_csv() to emit "1234.0" which breaks PostgreSQL BIGINT COPY.
    Nullable Int64 preserves NULLs without the trailing .0 in CSV output.
    """
    logger.info("Coercing integer columns to nullable Int64")
    out = df.copy()
    coerced = 0
    for col in INT_COLUMNS:
        if col not in out.columns:
            continue
        # to_numeric handles edge strings; floor any pre-existing floats first
        # so 1234.0 → 1234, not a parse error
        numeric = pd.to_numeric(out[col], errors="coerce")
        # Round to handle any float imprecision (e.g., 1.9999999... → 2)
        out[col] = numeric.round().astype("Int64")
        coerced += 1
    logger.debug(f"  Coerced {coerced} columns to Int64")
    return out

def apply_surrogate_keys(
    df: pd.DataFrame,
    asset_map: dict,
    port_map: dict,
    attack_map: dict,
    protocol_map: dict,
) -> pd.DataFrame:
    """
    Replace text/numeric source values with surrogate keys.
    Returns a new DataFrame with FACT_COLUMNS in order.
    """
    logger.info("Applying surrogate key mappings")
    out = df.copy()

    out["source_system"] = "CICIDS"
    out["src_asset_sk"] = out["src_ip"].map(asset_map)
    out["dest_asset_sk"] = out["dest_ip"].map(asset_map)
    out["src_port_sk"] = out["src_port"].map(port_map)
    out["dest_port_sk"] = out["dest_port"].map(port_map)
    out["attack_sk"] = out["attack_label"].map(attack_map)
    out["protocol_sk"] = out["protocol_num"].map(protocol_map)

    # Validate FK resolution rates
    fk_metrics = {
        "src_asset_sk": (out["src_asset_sk"].notna().sum() / len(out)) * 100,
        "dest_asset_sk": (out["dest_asset_sk"].notna().sum() / len(out)) * 100,
        "src_port_sk": (out["src_port_sk"].notna().sum() / len(out)) * 100,
        "dest_port_sk": (out["dest_port_sk"].notna().sum() / len(out)) * 100,
        "attack_sk": (out["attack_sk"].notna().sum() / len(out)) * 100,
        "protocol_sk": (out["protocol_sk"].notna().sum() / len(out)) * 100,
    }
    logger.info(f"FK resolution rates: {fk_metrics}")

    # Select only the columns the fact table needs, in order
    missing = set(FACT_COLUMNS) - set(out.columns)
    if missing:
        raise ValueError(f"Missing required fact columns: {missing}")

    out = out[FACT_COLUMNS].copy()
    out = coerce_integer_columns(out)
    return out


# ---------------------------------------------------------------------
# STEP 5 & 6: TRUNCATE + COPY load
# ---------------------------------------------------------------------

def bulk_load_facts(df: pd.DataFrame, truncate: bool = True) -> int:
    """
    Write fact_security_event using PostgreSQL COPY.
    Returns row count loaded.
    """
    temp_dir = _get_temp_dir()
    temp_csv = temp_dir / "fact_security_event.csv"

    logger.info(f"Writing {len(df):,} rows to temp CSV: {temp_csv}")
    t0 = time.time()
    df.to_csv(temp_csv, index=False, na_rep=r"\N")
    csv_size_mb = temp_csv.stat().st_size / 1e6
    logger.info(f"  CSV written in {time.time()-t0:.1f}s ({csv_size_mb:.1f} MB)")

    # Direct psycopg2 connection (SQLAlchemy doesn't expose copy_expert cleanly)
    from src.warehouse.db import get_database_url
    import re

    # Parse the URL into psycopg2 params
    url = get_database_url()
    # postgresql+psycopg2://user:pass@host:port/dbname
    m = re.match(
        r"postgresql\+psycopg2://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)",
        url,
    )
    if not m:
        raise RuntimeError(f"Could not parse DATABASE_URL: {url}")
    user, password, host, port, dbname = m.groups()

    # We URL-quoted the password during engine setup, so reverse it
    from urllib.parse import unquote_plus
    password = unquote_plus(password)

    conn = psycopg2.connect(
        host=host, port=port, dbname=dbname,
        user=user, password=password,
    )
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            if truncate:
                logger.info("TRUNCATE warehouse.fact_security_event")
                cur.execute("TRUNCATE warehouse.fact_security_event RESTART IDENTITY")

            logger.info(f"COPY {csv_size_mb:.1f} MB into fact_security_event...")
            t0 = time.time()
            with open(temp_csv, "r", encoding="utf-8") as f:
                cur.copy_expert(
                    f"""
                    COPY warehouse.fact_security_event ({", ".join(FACT_COLUMNS)})
                    FROM STDIN WITH (FORMAT CSV, HEADER true, NULL '\\N')
                    """,
                    f,
                )
            elapsed = time.time() - t0

            # Confirm row count
            cur.execute("SELECT COUNT(*) FROM warehouse.fact_security_event")
            loaded = cur.fetchone()[0]

        conn.commit()
        logger.info(
            f"  COPY complete: {loaded:,} rows in {elapsed:.1f}s "
            f"({loaded/elapsed:,.0f} rows/sec)"
        )

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # Clean up temp CSV
    try:
        temp_csv.unlink()
    except Exception:
        pass

    return loaded


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

def run(ctx: PipelineContext) -> int:
    """
    Execute the full load: dim upserts + fact COPY.
    Returns rows loaded.
    """
    if ctx.transformed_df is None:
        raise ValueError("ctx.transformed_df is None — run transform.run(ctx) first")

    df = ctx.transformed_df
    enriched = ctx.enriched_ip_data or {}

    # Step 1: dim_asset
    asset_map = upsert_dim_asset(df, enriched)

    # Step 2: dim_port
    port_map = upsert_dim_port(df)

    # Step 3: dim FK maps (read-only)
    attack_map = build_attack_type_map()
    protocol_map = build_protocol_map()
    logger.info(
        f"FK maps ready: assets={len(asset_map):,}, ports={len(port_map):,}, "
        f"attacks={len(attack_map)}, protocols={len(protocol_map)}"
    )

    # Step 4: apply FKs to dataframe
    fact_df = apply_surrogate_keys(df, asset_map, port_map, attack_map, protocol_map)

    # Step 5 & 6: bulk load
    rows_loaded = bulk_load_facts(fact_df, truncate=ctx.truncate_facts)

    logger.info("Refreshing materialized views")
    engine = get_engine()
    with engine.begin() as conn:
        for mv in ["mv_attack_summary", "mv_top_attackers", "mv_hourly_threat_pattern"]:
            conn.execute(text(f"REFRESH MATERIALIZED VIEW warehouse.{mv}"))
    logger.info("Materialized views refreshed")

    ctx.rows_loaded = rows_loaded
    return rows_loaded