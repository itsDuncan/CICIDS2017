-- =====================================================================
-- SOC SENTINEL — PERFORMANCE INDEXES
-- File: sql/ddl/03_indexes.sql
-- Purpose: Indexes for common dashboard query patterns
-- Run AFTER 02_facts.sql
-- =====================================================================

SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- Dimension indexes (lookups by natural keys)
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_dim_date_full           ON warehouse.dim_date(full_date);
CREATE INDEX IF NOT EXISTS idx_dim_date_year_month     ON warehouse.dim_date(year, month_num);

CREATE INDEX IF NOT EXISTS idx_dim_asset_identifier    ON warehouse.dim_asset(asset_identifier);
CREATE INDEX IF NOT EXISTS idx_dim_asset_ip            ON warehouse.dim_asset(ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dim_asset_country       ON warehouse.dim_asset(country_iso) WHERE country_iso IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dim_asset_source        ON warehouse.dim_asset(source_system);

CREATE INDEX IF NOT EXISTS idx_dim_user_id             ON warehouse.dim_user(user_id);
CREATE INDEX IF NOT EXISTS idx_dim_user_current        ON warehouse.dim_user(user_id) WHERE is_current = 1;
CREATE INDEX IF NOT EXISTS idx_dim_user_dept           ON warehouse.dim_user(department) WHERE is_current = 1;
CREATE INDEX IF NOT EXISTS idx_dim_user_malicious      ON warehouse.dim_user(is_malicious) WHERE is_malicious = 1;

CREATE INDEX IF NOT EXISTS idx_dim_attack_family       ON warehouse.dim_attack_type(attack_family);
CREATE INDEX IF NOT EXISTS idx_dim_port_number         ON warehouse.dim_port(port_number);

-- ---------------------------------------------------------------------
-- Fact table indexes
-- ---------------------------------------------------------------------
-- fact_security_event — common query patterns:
--   "Show attacks by time", "Top attacker IPs", "Filter by attack family"
CREATE INDEX IF NOT EXISTS idx_fact_sec_date           ON warehouse.fact_security_event(date_sk);
CREATE INDEX IF NOT EXISTS idx_fact_sec_time           ON warehouse.fact_security_event(time_sk);
CREATE INDEX IF NOT EXISTS idx_fact_sec_event_time     ON warehouse.fact_security_event(event_time);
CREATE INDEX IF NOT EXISTS idx_fact_sec_attack         ON warehouse.fact_security_event(attack_sk);
CREATE INDEX IF NOT EXISTS idx_fact_sec_src_asset      ON warehouse.fact_security_event(src_asset_sk);
CREATE INDEX IF NOT EXISTS idx_fact_sec_dest_asset     ON warehouse.fact_security_event(dest_asset_sk);
CREATE INDEX IF NOT EXISTS idx_fact_sec_is_attack      ON warehouse.fact_security_event(is_attack) WHERE is_attack = 1;
CREATE INDEX IF NOT EXISTS idx_fact_sec_attack_family  ON warehouse.fact_security_event(attack_family_denorm);
CREATE INDEX IF NOT EXISTS idx_fact_sec_priority       ON warehouse.fact_security_event(priority_label) WHERE priority_label IS NOT NULL;

-- fact_user_activity — common query patterns:
--   "Show user X's activity", "After-hours USB events", "Activity by department"
CREATE INDEX IF NOT EXISTS idx_fact_act_date           ON warehouse.fact_user_activity(date_sk);
CREATE INDEX IF NOT EXISTS idx_fact_act_time           ON warehouse.fact_user_activity(time_sk);
CREATE INDEX IF NOT EXISTS idx_fact_act_event_time     ON warehouse.fact_user_activity(event_time);
CREATE INDEX IF NOT EXISTS idx_fact_act_user           ON warehouse.fact_user_activity(user_sk);
CREATE INDEX IF NOT EXISTS idx_fact_act_asset          ON warehouse.fact_user_activity(asset_sk);
CREATE INDEX IF NOT EXISTS idx_fact_act_type           ON warehouse.fact_user_activity(activity_sk);
CREATE INDEX IF NOT EXISTS idx_fact_act_after_hours    ON warehouse.fact_user_activity(is_after_hours) WHERE is_after_hours = 1;
CREATE INDEX IF NOT EXISTS idx_fact_act_in_attack      ON warehouse.fact_user_activity(in_attack_window) WHERE in_attack_window = 1;
CREATE INDEX IF NOT EXISTS idx_fact_act_malicious      ON warehouse.fact_user_activity(is_malicious_user) WHERE is_malicious_user = 1;

-- ---------------------------------------------------------------------
-- Composite indexes for common dashboard queries
-- ---------------------------------------------------------------------
-- "Attacks per hour over time" — date + time + attack
CREATE INDEX IF NOT EXISTS idx_fact_sec_date_time_attack
    ON warehouse.fact_security_event(date_sk, time_sk, attack_sk);

-- "User activity timeline" — user + date + time
CREATE INDEX IF NOT EXISTS idx_fact_act_user_date_time
    ON warehouse.fact_user_activity(user_sk, date_sk, time_sk);

-- =====================================================================
-- VERIFICATION
-- =====================================================================
SELECT
    schemaname,
    tablename,
    COUNT(*) AS index_count
FROM pg_indexes
WHERE schemaname = 'warehouse'
GROUP BY schemaname, tablename
ORDER BY tablename;