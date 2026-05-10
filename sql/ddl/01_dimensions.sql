-- =====================================================================
-- SOC SENTINEL — DIMENSION TABLES
-- File: sql/ddl/01_dimensions.sql
-- Purpose: Create all 8 dimension tables for the unified SOC warehouse
-- Schema: warehouse
-- =====================================================================

-- Ensure schema exists
CREATE SCHEMA IF NOT EXISTS warehouse;
SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- 1. dim_date — Calendar dimension (shared by both facts)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_date CASCADE;
CREATE TABLE warehouse.dim_date (
    date_sk            INTEGER PRIMARY KEY,        -- YYYYMMDD format (e.g., 20170703)
    full_date          DATE NOT NULL UNIQUE,
    day_of_week        SMALLINT NOT NULL,          -- 1=Monday, 7=Sunday (ISO)
    day_name           VARCHAR(10) NOT NULL,
    day_of_month       SMALLINT NOT NULL,
    day_of_year        SMALLINT NOT NULL,
    week_of_year       SMALLINT NOT NULL,
    month_num          SMALLINT NOT NULL,
    month_name         VARCHAR(10) NOT NULL,
    quarter            SMALLINT NOT NULL,
    year               SMALLINT NOT NULL,
    is_weekend         SMALLINT NOT NULL DEFAULT 0,
    is_business_day    SMALLINT NOT NULL DEFAULT 1,
    holiday_flag       SMALLINT NOT NULL DEFAULT 0,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_date IS 'Calendar dimension covering 2010-2017 to span both CERT and CICIDS datasets';
COMMENT ON COLUMN warehouse.dim_date.date_sk IS 'Surrogate key in YYYYMMDD integer format';

-- ---------------------------------------------------------------------
-- 2. dim_time — Time-of-day dimension (shared)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_time CASCADE;
CREATE TABLE warehouse.dim_time (
    time_sk            SMALLINT PRIMARY KEY,       -- 0-1439 (one row per minute)
    hour_24            SMALLINT NOT NULL,          -- 0-23
    minute             SMALLINT NOT NULL,          -- 0-59
    hour_12            SMALLINT NOT NULL,          -- 1-12
    am_pm              CHAR(2) NOT NULL,
    day_part           VARCHAR(20) NOT NULL,       -- 'late_night', 'early_morning', 'morning', 'afternoon', 'evening', 'night'
    is_business_hour   SMALLINT NOT NULL DEFAULT 0,
    is_after_hours     SMALLINT NOT NULL DEFAULT 0,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_time IS '1-minute granularity time dimension (1440 rows total)';
COMMENT ON COLUMN warehouse.dim_time.is_after_hours IS 'Critical insider threat feature: 1 if outside 7am-7pm';

-- ---------------------------------------------------------------------
-- 3. dim_asset — Devices/hosts (shared by both fact tables)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_asset CASCADE;
CREATE TABLE warehouse.dim_asset (
    asset_sk           BIGSERIAL PRIMARY KEY,
    asset_identifier   VARCHAR(50) NOT NULL,       -- IP address (CICIDS) or PC name (CERT)
    asset_type         VARCHAR(20) NOT NULL,       -- 'host', 'pc', 'server', 'router', 'unknown'
    ip_address         VARCHAR(50),                -- populated for CICIDS, NULL for CERT
    mac_address        VARCHAR(20),
    hostname           VARCHAR(100),
    os_type            VARCHAR(50),
    business_unit      VARCHAR(100),
    criticality        VARCHAR(20) DEFAULT 'medium',  -- 'low', 'medium', 'high', 'critical'
    is_internal        SMALLINT NOT NULL DEFAULT 1,
    -- Geographic enrichment (populated by Week 3 ETL via MaxMind)
    country_iso        VARCHAR(2),
    country_name       VARCHAR(100),
    city               VARCHAR(100),
    latitude           DECIMAL(9,6),
    longitude          DECIMAL(9,6),
    asn                INTEGER,
    asn_org            VARCHAR(200),
    -- Reputation enrichment (Week 3 ETL via AbuseIPDB)
    abuse_confidence   SMALLINT,                   -- 0-100
    is_known_attacker  SMALLINT DEFAULT 0,
    -- Metadata
    source_system      VARCHAR(20) NOT NULL,       -- 'CICIDS', 'CERT', 'EXTERNAL'
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Each (asset_identifier, source_system) combination is unique
    CONSTRAINT uq_dim_asset_identifier UNIQUE (asset_identifier, source_system)
);

COMMENT ON TABLE warehouse.dim_asset IS 'Unified asset dimension: CICIDS network hosts (by IP) and CERT employee PCs (by name)';

-- ---------------------------------------------------------------------
-- 4. dim_user — Employees with SCD2 history (CERT-specific)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_user CASCADE;
CREATE TABLE warehouse.dim_user (
    user_sk             BIGSERIAL PRIMARY KEY,
    user_id             VARCHAR(20) NOT NULL,       -- e.g., 'CEL0561'
    employee_name       VARCHAR(200),
    email_address       VARCHAR(200),
    role                VARCHAR(100),
    business_unit       VARCHAR(50),
    functional_unit     VARCHAR(100),
    department          VARCHAR(100),
    team                VARCHAR(50),
    supervisor_name     VARCHAR(200),               -- supervisor's name from LDAP
    -- Psychometric (OCEAN) — static per user
    ocean_o             SMALLINT,                   -- Openness
    ocean_c             SMALLINT,                   -- Conscientiousness
    ocean_e             SMALLINT,                   -- Extraversion
    ocean_a             SMALLINT,                   -- Agreeableness
    ocean_n             SMALLINT,                   -- Neuroticism
    -- Insider threat labels (from CMU answer key)
    is_malicious        SMALLINT NOT NULL DEFAULT 0,
    malicious_scenario  SMALLINT,                   -- 1, 2, 3, or NULL
    attack_window_start TIMESTAMP,
    attack_window_end   TIMESTAMP,
    -- SCD Type 2 fields
    valid_from          DATE NOT NULL,
    valid_to            DATE,                       -- NULL = currently valid
    is_current          SMALLINT NOT NULL DEFAULT 1,
    -- Metadata
    source_system       VARCHAR(20) NOT NULL DEFAULT 'CERT',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_user IS 'Employee dimension with SCD2 history from monthly LDAP snapshots';
COMMENT ON COLUMN warehouse.dim_user.is_current IS '1 if this row reflects current organizational state';

-- ---------------------------------------------------------------------
-- 5. dim_activity_type — CERT activity taxonomy
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_activity_type CASCADE;
CREATE TABLE warehouse.dim_activity_type (
    activity_sk         SMALLSERIAL PRIMARY KEY,
    activity_name       VARCHAR(50) NOT NULL UNIQUE,    -- 'Logon', 'Logoff', 'Connect', 'Disconnect', 'File Access', 'Email Send'
    activity_category   VARCHAR(30) NOT NULL,           -- 'authentication', 'device', 'file', 'email', 'web'
    risk_weight         DECIMAL(3,1) DEFAULT 1.0,       -- baseline risk (USB Connect=3.0, Logon=1.0)
    description         TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_activity_type IS 'Taxonomy of CERT employee activity types';

-- ---------------------------------------------------------------------
-- 6. dim_attack_type — CICIDS attack taxonomy
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_attack_type CASCADE;
CREATE TABLE warehouse.dim_attack_type (
    attack_sk           SMALLSERIAL PRIMARY KEY,
    attack_label        VARCHAR(100) NOT NULL UNIQUE,   -- 'BENIGN', 'DoS Hulk', 'Web Attack - XSS', etc.
    attack_family       VARCHAR(50) NOT NULL,           -- 'Benign', 'DoS', 'DDoS', 'Brute Force', etc.
    severity            VARCHAR(20) NOT NULL DEFAULT 'medium',  -- 'info', 'low', 'medium', 'high', 'critical'
    mitre_technique_id  VARCHAR(20),                    -- e.g., 'T1190'
    mitre_tactic        VARCHAR(50),                    -- e.g., 'Initial Access'
    description         TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_attack_type IS 'Taxonomy of network attacks observed in CICIDS2017';

-- ---------------------------------------------------------------------
-- 7. dim_protocol — Network protocols
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_protocol CASCADE;
CREATE TABLE warehouse.dim_protocol (
    protocol_sk     SMALLSERIAL PRIMARY KEY,
    protocol_num    SMALLINT NOT NULL UNIQUE,           -- IANA assigned: 6=TCP, 17=UDP, 1=ICMP
    protocol_name   VARCHAR(20) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_protocol IS 'IANA-registered network protocol numbers';

-- ---------------------------------------------------------------------
-- 8. dim_port — Service ports (lazily populated)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.dim_port CASCADE;
CREATE TABLE warehouse.dim_port (
    port_sk         SERIAL PRIMARY KEY,
    port_number     INTEGER NOT NULL UNIQUE,            -- 0-65535
    service_name    VARCHAR(50),                        -- 'HTTP', 'HTTPS', 'SSH', etc.
    port_category   VARCHAR(30) NOT NULL DEFAULT 'unknown',  -- 'web', 'mail', 'database', 'remote_access', 'ephemeral'
    is_well_known   SMALLINT NOT NULL DEFAULT 0,        -- 1 if port < 1024
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE warehouse.dim_port IS 'Service port catalog — populated only with ports observed in data + well-known ports';

-- =====================================================================
-- VERIFICATION
-- =====================================================================
SELECT
    table_name,
    (SELECT count(*) FROM information_schema.columns
     WHERE table_schema = 'warehouse' AND table_name = t.table_name) AS column_count
FROM information_schema.tables t
WHERE table_schema = 'warehouse'
  AND table_name LIKE 'dim_%'
ORDER BY table_name;

-- Expected output: 8 rows (dim_activity_type, dim_asset, dim_attack_type, dim_date, dim_port, dim_protocol, dim_time, dim_user)