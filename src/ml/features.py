"""
Feature definitions for ML models.

Defines the columns used as features and labels, plus helper utilities
to slice them out of a fact-table query result.
"""


# ---------------------------------------------------------------------
# Feature groups (from fact_security_event)
# ---------------------------------------------------------------------

# Flow volumetric features (counts, byte rates) — STRONG signal for DoS/DDoS
VOLUMETRIC_FEATURES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd",
    "total_length_bwd",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_pkts_per_sec",
    "bwd_pkts_per_sec",
    "down_up_ratio",
]

# Packet length statistics — STRONG signal for protocol anomalies
PACKET_LEN_FEATURES = [
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_variance",
    "avg_pkt_size", "avg_fwd_seg_size", "avg_bwd_seg_size",
]

# Inter-arrival time features — STRONG signal for botnet (regular intervals)
IAT_FEATURES = [
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
]

# TCP flag counts — STRONG signal for SYN floods, port scans
FLAG_FEATURES = [
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
]

# Header lengths
HEADER_FEATURES = [
    "fwd_header_length", "bwd_header_length",
]

# Bulk transfer features
BULK_FEATURES = [
    "fwd_avg_bytes_bulk", "fwd_avg_pkts_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk", "bwd_avg_pkts_bulk", "bwd_avg_bulk_rate",
]

# Subflow features
SUBFLOW_FEATURES = [
    "subflow_fwd_pkts", "subflow_fwd_bytes",
    "subflow_bwd_pkts", "subflow_bwd_bytes",
]

# TCP window features
WINDOW_FEATURES = [
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "act_data_pkt_fwd", "min_seg_size_fwd",
]

# Active/idle timing
TIMING_FEATURES = [
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]

# Categorical features (handle separately — one-hot or label encoded)
CATEGORICAL_FEATURES = [
    "protocol_sk",       # FK to dim_protocol; effectively a categorical
    "src_port_sk",       # very high cardinality — likely skip or bucket
    "dest_port_sk",      # moderate cardinality — encode as well-known/ephemeral
]


# ---------------------------------------------------------------------
# Master lists
# ---------------------------------------------------------------------

# All numeric features for tree-based models (Random Forest, XGBoost, Isolation Forest)
NUMERIC_FEATURES = (
    VOLUMETRIC_FEATURES
    + PACKET_LEN_FEATURES
    + IAT_FEATURES
    + FLAG_FEATURES
    + HEADER_FEATURES
    + BULK_FEATURES
    + SUBFLOW_FEATURES
    + WINDOW_FEATURES
    + TIMING_FEATURES
)

# Labels (Y values for supervised learning)
LABEL_COLUMNS = [
    "is_attack",              # binary: 0=benign, 1=attack
    "attack_family_denorm",   # multi-class: 'Benign', 'DoS', 'DDoS', etc.
]

# Identifier columns kept for debugging / dashboard linkage (NOT features)
ID_COLUMNS = [
    "event_id",
    "event_time",
    "date_sk",
    "time_sk",
    "src_asset_sk",
    "dest_asset_sk",
]


def get_feature_count() -> dict:
    """Return a count of each feature group, for documentation."""
    return {
        "volumetric": len(VOLUMETRIC_FEATURES),
        "packet_length": len(PACKET_LEN_FEATURES),
        "iat": len(IAT_FEATURES),
        "flags": len(FLAG_FEATURES),
        "headers": len(HEADER_FEATURES),
        "bulk": len(BULK_FEATURES),
        "subflow": len(SUBFLOW_FEATURES),
        "window": len(WINDOW_FEATURES),
        "timing": len(TIMING_FEATURES),
        "categorical": len(CATEGORICAL_FEATURES),
        "total_numeric": len(NUMERIC_FEATURES),
    }


if __name__ == "__main__":
    print("Feature group breakdown:")
    for group, count in get_feature_count().items():
        print(f"  {group:<15} {count:>3}")