"""
Transform stage — derive analytics-ready columns from extracted CICIDS data.

Transforms input from extract.py into a DataFrame ready for enrichment and load.
Adds derived keys (date_sk, time_sk) and classification fields (is_after_hours,
ip_class), without yet performing any external lookups or DB writes.
"""
import ipaddress
from typing import Optional

import pandas as pd

from src.etl.context import PipelineContext
from src.etl.logger import get_logger

logger = get_logger("transform")


# ---------------------------------------------------------------------
# Date / time key derivation
# ---------------------------------------------------------------------

def derive_date_sk(ts: pd.Series) -> pd.Series:
    """
    Convert timestamp to YYYYMMDD integer surrogate key.
    Matches dim_date.date_sk format.
    """
    return (ts.dt.year * 10000 + ts.dt.month * 100 + ts.dt.day).astype("int32")


def derive_time_sk(ts: pd.Series) -> pd.Series:
    """
    Convert timestamp to minute-of-day (0-1439) surrogate key.
    Matches dim_time.time_sk format.
    """
    return (ts.dt.hour * 60 + ts.dt.minute).astype("int16")


def derive_is_after_hours(ts: pd.Series) -> pd.Series:
    """1 if event outside 7am-7pm business window."""
    hour = ts.dt.hour
    return ((hour < 7) | (hour >= 19)).astype("int8")


def derive_is_weekend(ts: pd.Series) -> pd.Series:
    """1 if event on Saturday or Sunday."""
    return (ts.dt.dayofweek >= 5).astype("int8")


# ---------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------

def _classify_ip(ip_str: Optional[str]) -> str:
    """Classify a single IP address.

    Returns one of: 'internal', 'external', 'special', 'invalid'.
    Centralized so behavior is consistent with EDA findings.
    """
    if pd.isna(ip_str) or not ip_str:
        return "invalid"
    try:
        ip = ipaddress.ip_address(str(ip_str))
        if ip.is_private:
            return "internal"
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return "special"
        return "external"
    except (ValueError, TypeError):
        return "invalid"


def classify_ip_series(s: pd.Series) -> pd.Series:
    """Vectorized IP classification using a cache for distinct IPs."""
    # Cache unique IPs since CICIDS has many repeats (e.g., 192.168.10.50 = web server)
    unique_ips = s.dropna().unique()
    logger.debug(f"Classifying {len(unique_ips):,} unique IPs")
    classification = {ip: _classify_ip(ip) for ip in unique_ips}
    return s.map(classification).fillna("invalid").astype("category")


# ---------------------------------------------------------------------
# Port normalization
# ---------------------------------------------------------------------

def normalize_port(s: pd.Series) -> pd.Series:
    """Coerce port column to nullable integer in 0-65535 range."""
    ports = pd.to_numeric(s, errors="coerce")
    # Out-of-range ports become NaN
    ports = ports.where((ports >= 0) & (ports <= 65535))
    return ports.astype("Int32")  # nullable int


# ---------------------------------------------------------------------
# Column renaming map — from parquet source → warehouse target
# ---------------------------------------------------------------------
# Maps the messy source column names (with spaces, slashes, mixed case)
# to clean snake_case names matching fact_security_event.
SOURCE_TO_FACT_COLUMNS = {
    # Identity
    "Flow ID": "flow_id",
    "Source IP": "src_ip",
    "Destination IP": "dest_ip",
    "Source Port": "src_port",
    "Destination Port": "dest_port",
    # Time
    "event_time": "event_time",
    # Flow volumetric
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_length_fwd",
    "Total Length of Bwd Packets": "total_length_bwd",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    # Packet length statistics
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_variance",
    # IAT statistics
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_total",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_total",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    # Flag counts
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "URG Flag Count": "urg_flag_count",
    "CWE Flag Count": "cwe_flag_count",
    "ECE Flag Count": "ece_flag_count",
    # Header lengths and rates
    "Fwd Header Length": "fwd_header_length",
    "Bwd Header Length": "bwd_header_length",
    "Fwd Packets/s": "fwd_pkts_per_sec",
    "Bwd Packets/s": "bwd_pkts_per_sec",
    # Other measures
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_pkt_size",
    "Avg Fwd Segment Size": "avg_fwd_seg_size",
    "Avg Bwd Segment Size": "avg_bwd_seg_size",
    # Bulk measures
    "Fwd Avg Bytes/Bulk": "fwd_avg_bytes_bulk",
    "Fwd Avg Packets/Bulk": "fwd_avg_pkts_bulk",
    "Fwd Avg Bulk Rate": "fwd_avg_bulk_rate",
    "Bwd Avg Bytes/Bulk": "bwd_avg_bytes_bulk",
    "Bwd Avg Packets/Bulk": "bwd_avg_pkts_bulk",
    "Bwd Avg Bulk Rate": "bwd_avg_bulk_rate",
    # Subflow measures
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_bytes",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_bytes",
    # Window sizes
    "Init_Win_bytes_forward": "init_win_bytes_fwd",
    "Init_Win_bytes_backward": "init_win_bytes_bwd",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "min_seg_size_forward": "min_seg_size_fwd",
    # Active/idle measures
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
    # Labels (kept as-is, used for FK lookup against dim_attack_type)
    "label_clean": "attack_label",            # joins to dim_attack_type.attack_label
    "attack_family": "attack_family_denorm",  # denormalized for query speed
    "is_attack": "is_attack",
    # Pass-through for context
    "Protocol": "protocol_num",               # joins to dim_protocol.protocol_num
}


# ---------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------

def validate_post_transform(df: pd.DataFrame) -> None:
    """Sanity checks before handing off to enrich/load."""
    # All rows must have a valid date_sk
    if df["date_sk"].isna().any():
        raise ValueError("Found rows with NULL date_sk after transform — unexpected")

    # date_sk should be in CICIDS range (20170703 to 20170707)
    min_sk, max_sk = df["date_sk"].min(), df["date_sk"].max()
    if min_sk < 20170703 or max_sk > 20170707:
        logger.warning(f"date_sk range ({min_sk} to {max_sk}) outside expected CICIDS window")

    # time_sk should be 0-1439
    bad_times = df[(df["time_sk"] < 0) | (df["time_sk"] > 1439)]
    if len(bad_times) > 0:
        raise ValueError(f"Found {len(bad_times)} rows with invalid time_sk")

    # All rows should have classifiable IPs
    invalid_src = (df["src_ip_class"] == "invalid").sum()
    invalid_dest = (df["dest_ip_class"] == "invalid").sum()
    if invalid_src > 0 or invalid_dest > 0:
        logger.warning(f"Invalid IPs: src={invalid_src}, dest={invalid_dest}")


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

def run(ctx: PipelineContext) -> pd.DataFrame:
    """
    Transform the extracted DataFrame.

    Reads ctx.extracted_df, writes ctx.transformed_df, and updates ctx.rows_transformed.
    """
    if ctx.extracted_df is None:
        raise ValueError("ctx.extracted_df is None — run extract.run(ctx) first")

    df = ctx.extracted_df
    logger.info(f"Transforming {len(df):,} rows")

    # ----- Step 1: Rename columns to warehouse-friendly names -----
    df = df.rename(columns=SOURCE_TO_FACT_COLUMNS)
    logger.debug(f"Renamed {len(SOURCE_TO_FACT_COLUMNS)} columns")

    # ----- Step 2: Derive time-based surrogate keys -----
    logger.info("Deriving date_sk, time_sk, is_after_hours, is_weekend")
    df["date_sk"] = derive_date_sk(df["event_time"])
    df["time_sk"] = derive_time_sk(df["event_time"])
    df["is_after_hours"] = derive_is_after_hours(df["event_time"])
    df["is_weekend"] = derive_is_weekend(df["event_time"])

    # ----- Step 3: Classify IPs (internal/external/special/invalid) -----
    logger.info("Classifying source IPs")
    df["src_ip_class"] = classify_ip_series(df["src_ip"])
    logger.info("Classifying destination IPs")
    df["dest_ip_class"] = classify_ip_series(df["dest_ip"])

    src_dist = df["src_ip_class"].value_counts().to_dict()
    dest_dist = df["dest_ip_class"].value_counts().to_dict()
    logger.info(f"Source IP classification: {src_dist}")
    logger.info(f"Destination IP classification: {dest_dist}")

    # ----- Step 4: Normalize ports -----
    df["src_port"] = normalize_port(df["src_port"])
    df["dest_port"] = normalize_port(df["dest_port"])

    # ----- Step 5: Coerce protocol to nullable int -----
    df["protocol_num"] = pd.to_numeric(df["protocol_num"], errors="coerce").astype("Int16")

    # ----- Step 6: Validate -----
    validate_post_transform(df)

    # ----- Step 7: Update context -----
    ctx.transformed_df = df
    ctx.rows_transformed = len(df)

    # Free extract reference to release memory
    ctx.extracted_df = None

    logger.info(f"Transform complete: {len(df):,} rows × {len(df.columns)} columns")
    return df