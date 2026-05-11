-- =====================================================================
-- SOC SENTINEL — MATERIALIZED VIEWS (Performance Optimization)
-- File: sql/ddl/07_materialized_views.sql
-- Run AFTER 04_views.sql and after fact table is populated.
-- =====================================================================

SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- mv_attack_summary — Daily attack KPIs (replaces v_attack_summary)
-- ---------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS warehouse.mv_attack_summary CASCADE;
CREATE MATERIALIZED VIEW warehouse.mv_attack_summary AS
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

CREATE INDEX idx_mv_attack_summary_date ON warehouse.mv_attack_summary(full_date);
CREATE INDEX idx_mv_attack_summary_family ON warehouse.mv_attack_summary(attack_family);

-- ---------------------------------------------------------------------
-- mv_top_attackers — Geographic threat origin (replaces v_top_attackers)
-- ---------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS warehouse.mv_top_attackers CASCADE;
CREATE MATERIALIZED VIEW warehouse.mv_top_attackers AS
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

CREATE INDEX idx_mv_top_attackers_country ON warehouse.mv_top_attackers(country_iso);
CREATE INDEX idx_mv_top_attackers_count ON warehouse.mv_top_attackers(attack_count DESC);

-- ---------------------------------------------------------------------
-- mv_hourly_threat_pattern — Hour-of-day heatmap data
-- ---------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS warehouse.mv_hourly_threat_pattern CASCADE;
CREATE MATERIALIZED VIEW warehouse.mv_hourly_threat_pattern AS
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

CREATE INDEX idx_mv_hourly_day ON warehouse.mv_hourly_threat_pattern(day_name);

-- ---------------------------------------------------------------------
-- Refresh helper — call after each ETL run
-- ---------------------------------------------------------------------
-- To refresh manually:
--   REFRESH MATERIALIZED VIEW warehouse.mv_attack_summary;
--   REFRESH MATERIALIZED VIEW warehouse.mv_top_attackers;
--   REFRESH MATERIALIZED VIEW warehouse.mv_hourly_threat_pattern;

SELECT 'Materialized views created' AS status,
       (SELECT COUNT(*) FROM warehouse.mv_attack_summary) AS mv_attack_rows,
       (SELECT COUNT(*) FROM warehouse.mv_top_attackers) AS mv_attackers_rows,
       (SELECT COUNT(*) FROM warehouse.mv_hourly_threat_pattern) AS mv_hourly_rows;