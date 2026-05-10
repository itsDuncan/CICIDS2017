-- =====================================================================
-- SOC SENTINEL — FACT TABLES
-- File: sql/ddl/02_facts.sql
-- Purpose: Create both fact tables with FK constraints to dimensions
-- Run AFTER 01_dimensions.sql
-- =====================================================================

SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- fact_security_event — CICIDS network flows (Phase 1)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.fact_security_event CASCADE;
CREATE TABLE warehouse.fact_security_event (
    event_id              BIGSERIAL PRIMARY KEY,
    source_system         VARCHAR(20) NOT NULL DEFAULT 'CICIDS',
    -- Foreign keys
    date_sk               INTEGER NOT NULL REFERENCES warehouse.dim_date(date_sk),
    time_sk               SMALLINT NOT NULL REFERENCES warehouse.dim_time(time_sk),
    src_asset_sk          BIGINT REFERENCES warehouse.dim_asset(asset_sk),
    dest_asset_sk         BIGINT REFERENCES warehouse.dim_asset(asset_sk),
    src_port_sk           INTEGER REFERENCES warehouse.dim_port(port_sk),
    dest_port_sk          INTEGER REFERENCES warehouse.dim_port(port_sk),
    protocol_sk           SMALLINT REFERENCES warehouse.dim_protocol(protocol_sk),
    attack_sk             SMALLINT REFERENCES warehouse.dim_attack_type(attack_sk),
    -- Natural timestamp (kept for direct queries)
    event_time            TIMESTAMP NOT NULL,
    -- Flow identifiers
    flow_id               VARCHAR(100),
    -- Volumetric measures
    flow_duration         BIGINT,
    total_fwd_packets     INTEGER,
    total_bwd_packets     INTEGER,
    total_length_fwd      INTEGER,
    total_length_bwd      INTEGER,
    flow_bytes_per_sec    DOUBLE PRECISION,
    flow_packets_per_sec  DOUBLE PRECISION,
    -- Packet length statistics
    fwd_pkt_len_max       INTEGER,
    fwd_pkt_len_min       INTEGER,
    fwd_pkt_len_mean      DOUBLE PRECISION,
    fwd_pkt_len_std       DOUBLE PRECISION,
    bwd_pkt_len_max       INTEGER,
    bwd_pkt_len_min       INTEGER,
    bwd_pkt_len_mean      DOUBLE PRECISION,
    bwd_pkt_len_std       DOUBLE PRECISION,
    pkt_len_min           INTEGER,
    pkt_len_max           INTEGER,
    pkt_len_mean          DOUBLE PRECISION,
    pkt_len_std           DOUBLE PRECISION,
    pkt_len_variance      DOUBLE PRECISION,
    -- Inter-arrival times
    flow_iat_mean         DOUBLE PRECISION,
    flow_iat_std          DOUBLE PRECISION,
    flow_iat_max          BIGINT,
    flow_iat_min          BIGINT,
    fwd_iat_total         BIGINT,
    fwd_iat_mean          DOUBLE PRECISION,
    fwd_iat_std           DOUBLE PRECISION,
    fwd_iat_max           BIGINT,
    fwd_iat_min           BIGINT,
    bwd_iat_total         BIGINT,
    bwd_iat_mean          DOUBLE PRECISION,
    bwd_iat_std           DOUBLE PRECISION,
    bwd_iat_max           BIGINT,
    bwd_iat_min           BIGINT,
    -- Flag counts
    fwd_psh_flags         SMALLINT,
    bwd_psh_flags         SMALLINT,
    fwd_urg_flags         SMALLINT,
    bwd_urg_flags         SMALLINT,
    fin_flag_count        SMALLINT,
    syn_flag_count        SMALLINT,
    rst_flag_count        SMALLINT,
    psh_flag_count        SMALLINT,
    ack_flag_count        SMALLINT,
    urg_flag_count        SMALLINT,
    cwe_flag_count        SMALLINT,
    ece_flag_count        SMALLINT,
    -- Header lengths and rates
    fwd_header_length     INTEGER,
    bwd_header_length     INTEGER,
    fwd_pkts_per_sec      DOUBLE PRECISION,
    bwd_pkts_per_sec      DOUBLE PRECISION,
    -- Other measures
    down_up_ratio         SMALLINT,
    avg_pkt_size          DOUBLE PRECISION,
    avg_fwd_seg_size      DOUBLE PRECISION,
    avg_bwd_seg_size      DOUBLE PRECISION,
    -- Bulk measures
    fwd_avg_bytes_bulk    INTEGER,
    fwd_avg_pkts_bulk     INTEGER,
    fwd_avg_bulk_rate     INTEGER,
    bwd_avg_bytes_bulk    INTEGER,
    bwd_avg_pkts_bulk     INTEGER,
    bwd_avg_bulk_rate     INTEGER,
    -- Subflow measures
    subflow_fwd_pkts      INTEGER,
    subflow_fwd_bytes     INTEGER,
    subflow_bwd_pkts      INTEGER,
    subflow_bwd_bytes     INTEGER,
    -- Window sizes
    init_win_bytes_fwd    INTEGER,
    init_win_bytes_bwd    INTEGER,
    act_data_pkt_fwd      INTEGER,
    min_seg_size_fwd      INTEGER,
    -- Active/idle measures
    active_mean           DOUBLE PRECISION,
    active_std            DOUBLE PRECISION,
    active_max            BIGINT,
    active_min            BIGINT,
    idle_mean             DOUBLE PRECISION,
    idle_std              DOUBLE PRECISION,
    idle_max              BIGINT,
    idle_min              BIGINT,
    -- Labels
    is_attack             SMALLINT,                   -- 0=benign, 1=attack, NULL=unlabeled
    attack_family_denorm  VARCHAR(50),                -- denormalized for query speed
    -- ML output (populated in Week 4)
    priority_score        DECIMAL(5,4),               -- 0.0-1.0
    priority_label        VARCHAR(20),                -- 'critical','high','medium','low'
    anomaly_score         DECIMAL(5,4),
    model_version         VARCHAR(20),
    scored_at             TIMESTAMP,
    -- Audit
    loaded_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.fact_security_event IS 'CICIDS2017 network flow facts — populated by Week 3 ETL';

-- ---------------------------------------------------------------------
-- fact_user_activity — CERT employee behavior (Phase 2)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.fact_user_activity CASCADE;
CREATE TABLE warehouse.fact_user_activity (
    activity_id              BIGSERIAL PRIMARY KEY,
    source_system            VARCHAR(20) NOT NULL DEFAULT 'CERT',
    -- Foreign keys
    date_sk                  INTEGER NOT NULL REFERENCES warehouse.dim_date(date_sk),
    time_sk                  SMALLINT NOT NULL REFERENCES warehouse.dim_time(time_sk),
    user_sk                  BIGINT NOT NULL REFERENCES warehouse.dim_user(user_sk),
    asset_sk                 BIGINT REFERENCES warehouse.dim_asset(asset_sk),
    activity_sk              SMALLINT NOT NULL REFERENCES warehouse.dim_activity_type(activity_sk),
    -- Natural identifiers
    natural_event_id         VARCHAR(50),               -- the {X1D9-...} UUID from source
    event_time               TIMESTAMP NOT NULL,
    -- Activity-specific fields (sparse)
    filename                 VARCHAR(200),
    file_extension           VARCHAR(20),
    to_recipients_count      SMALLINT,
    external_recipient_count SMALLINT,
    attachment_count         SMALLINT,
    size_bytes               BIGINT,
    url_domain               VARCHAR(200),              -- Phase 2.5 when http.csv ingested
    -- Derived temporal features
    is_after_hours           SMALLINT,
    is_weekend               SMALLINT,
    -- Insider threat labels (denormalized from dim_user for query speed)
    is_malicious_user        SMALLINT NOT NULL DEFAULT 0,
    in_attack_window         SMALLINT NOT NULL DEFAULT 0,
    -- ML output (populated in Phase 2)
    risk_score               DECIMAL(5,4),
    anomaly_score            DECIMAL(5,4),
    model_version            VARCHAR(20),
    scored_at                TIMESTAMP,
    -- Audit
    loaded_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.fact_user_activity IS 'CERT r4.2 employee activity facts — populated in Phase 2';
COMMENT ON COLUMN warehouse.fact_user_activity.in_attack_window IS '1 if event_time falls within the user attack_window (positive ML class)';

-- =====================================================================
-- VERIFICATION
-- =====================================================================
SELECT
    table_name,
    (SELECT count(*) FROM information_schema.columns
     WHERE table_schema = 'warehouse' AND table_name = t.table_name) AS column_count,
    (SELECT count(*) FROM information_schema.table_constraints
     WHERE table_schema = 'warehouse' AND table_name = t.table_name AND constraint_type = 'FOREIGN KEY') AS fk_count
FROM information_schema.tables t
WHERE table_schema = 'warehouse'
  AND table_name LIKE 'fact_%'
ORDER BY table_name;

-- Expected: 2 rows
-- fact_security_event:  ~95 columns, 8 FKs
-- fact_user_activity:   ~26 columns, 5 FKs