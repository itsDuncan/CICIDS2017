-- =====================================================================
-- SOC SENTINEL — ANALYTICAL VIEWS
-- File: sql/ddl/04_views.sql
-- Purpose: Convenience views for the BI dashboard
-- Run AFTER 03_indexes.sql
-- =====================================================================

SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- v_attack_summary — High-level attack KPIs for executive dashboard
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW warehouse.v_attack_summary AS
SELECT
    d.full_date,
    d.day_name,
    at.attack_family,
    at.severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT f.src_asset_sk) AS unique_attackers,
    COUNT(DISTINCT f.dest_asset_sk) AS unique_targets,
    SUM(f.flow_bytes_per_sec) AS total_byte_throughput,
    AVG(f.flow_duration) AS avg_flow_duration_us
FROM warehouse.fact_security_event f
JOIN warehouse.dim_date d ON f.date_sk = d.date_sk
JOIN warehouse.dim_attack_type at ON f.attack_sk = at.attack_sk
WHERE f.is_attack = 1
GROUP BY d.full_date, d.day_name, at.attack_family, at.severity;

COMMENT ON VIEW warehouse.v_attack_summary IS 'Daily attack KPIs grouped by family — primary executive dashboard data source';

-- ---------------------------------------------------------------------
-- v_top_attackers — Geographic threat origin view
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW warehouse.v_top_attackers AS
SELECT
    a.asset_identifier AS attacker_ip,
    a.country_iso,
    a.country_name,
    a.city,
    a.latitude,
    a.longitude,
    a.asn_org,
    a.abuse_confidence,
    COUNT(*) AS attack_count,
    COUNT(DISTINCT f.dest_asset_sk) AS unique_targets,
    COUNT(DISTINCT at.attack_family) AS attack_families_used,
    MIN(f.event_time) AS first_seen,
    MAX(f.event_time) AS last_seen
FROM warehouse.fact_security_event f
JOIN warehouse.dim_asset a ON f.src_asset_sk = a.asset_sk
JOIN warehouse.dim_attack_type at ON f.attack_sk = at.attack_sk
WHERE f.is_attack = 1
  AND a.is_internal = 0
GROUP BY a.asset_identifier, a.country_iso, a.country_name, a.city,
         a.latitude, a.longitude, a.asn_org, a.abuse_confidence;

COMMENT ON VIEW warehouse.v_top_attackers IS 'External IPs ranked by attack volume — feeds the geographic map dashboard';

-- ---------------------------------------------------------------------
-- v_attack_targets — Internal asset threat exposure
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW warehouse.v_attack_targets AS
SELECT
    a.asset_identifier AS target_ip,
    a.asset_type,
    a.business_unit,
    a.criticality,
    COUNT(*) AS attacks_received,
    COUNT(DISTINCT f.src_asset_sk) AS unique_attackers,
    COUNT(DISTINCT at.attack_family) AS attack_families_seen,
    MIN(f.event_time) AS first_attacked,
    MAX(f.event_time) AS last_attacked
FROM warehouse.fact_security_event f
JOIN warehouse.dim_asset a ON f.dest_asset_sk = a.asset_sk
JOIN warehouse.dim_attack_type at ON f.attack_sk = at.attack_sk
WHERE f.is_attack = 1
GROUP BY a.asset_identifier, a.asset_type, a.business_unit, a.criticality;

COMMENT ON VIEW warehouse.v_attack_targets IS 'Internal hosts ranked by attack volume — feeds target risk dashboard';

-- ---------------------------------------------------------------------
-- v_user_risk_scoring — Insider threat user leaderboard (Phase 2)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW warehouse.v_user_risk_scoring AS
SELECT
    u.user_id,
    u.employee_name,
    u.role,
    u.department,
    u.team,
    u.ocean_o, u.ocean_c, u.ocean_e, u.ocean_a, u.ocean_n,
    u.is_malicious,
    u.malicious_scenario,
    COUNT(f.activity_id) AS total_events,
    SUM(f.is_after_hours) AS after_hours_events,
    SUM(CASE WHEN at.activity_category = 'device' THEN 1 ELSE 0 END) AS usb_events,
    SUM(CASE WHEN at.activity_category = 'email' THEN 1 ELSE 0 END) AS email_events,
    SUM(CASE WHEN at.activity_category = 'file' THEN 1 ELSE 0 END) AS file_events,
    AVG(f.risk_score) AS avg_risk_score,
    MAX(f.risk_score) AS max_risk_score
FROM warehouse.dim_user u
LEFT JOIN warehouse.fact_user_activity f ON u.user_sk = f.user_sk
LEFT JOIN warehouse.dim_activity_type at ON f.activity_sk = at.activity_sk
WHERE u.is_current = 1
GROUP BY u.user_id, u.employee_name, u.role, u.department, u.team,
         u.ocean_o, u.ocean_c, u.ocean_e, u.ocean_a, u.ocean_n,
         u.is_malicious, u.malicious_scenario;

COMMENT ON VIEW warehouse.v_user_risk_scoring IS 'Per-user risk profile — Phase 2 insider threat dashboard data source';

-- ---------------------------------------------------------------------
-- v_hourly_threat_pattern — For attack heatmap visualization
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW warehouse.v_hourly_threat_pattern AS
SELECT
    d.day_name,
    t.hour_24,
    t.day_part,
    at.attack_family,
    COUNT(*) AS event_count
FROM warehouse.fact_security_event f
JOIN warehouse.dim_date d ON f.date_sk = d.date_sk
JOIN warehouse.dim_time t ON f.time_sk = t.time_sk
JOIN warehouse.dim_attack_type at ON f.attack_sk = at.attack_sk
WHERE f.is_attack = 1
GROUP BY d.day_name, t.hour_24, t.day_part, at.attack_family;

COMMENT ON VIEW warehouse.v_hourly_threat_pattern IS 'Hour-of-day attack patterns — feeds heatmap visualizations';

-- =====================================================================
-- VERIFICATION
-- =====================================================================
SELECT
    table_name AS view_name,
    (SELECT count(*) FROM information_schema.columns
     WHERE table_schema = 'warehouse' AND table_name = v.table_name) AS column_count
FROM information_schema.views v
WHERE table_schema = 'warehouse'
ORDER BY view_name;