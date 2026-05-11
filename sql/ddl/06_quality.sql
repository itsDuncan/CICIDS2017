-- =====================================================================
-- SOC SENTINEL — DATA QUALITY TRACKING
-- File: sql/ddl/06_quality.sql
-- =====================================================================

SET search_path TO warehouse, public;

DROP TABLE IF EXISTS warehouse.meta_quality_checks CASCADE;
CREATE TABLE warehouse.meta_quality_checks (
    check_id          BIGSERIAL PRIMARY KEY,
    run_id            BIGINT REFERENCES warehouse.meta_pipeline_runs(run_id),
    check_name        VARCHAR(100) NOT NULL,
    check_category    VARCHAR(50) NOT NULL,
    severity          VARCHAR(20) NOT NULL DEFAULT 'warning',
    passed            SMALLINT NOT NULL,
    expected_value    TEXT,
    actual_value      TEXT,
    message           TEXT,
    executed_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_meta_quality_run ON warehouse.meta_quality_checks(run_id);
CREATE INDEX idx_meta_quality_failed ON warehouse.meta_quality_checks(passed) WHERE passed = 0;

COMMENT ON TABLE warehouse.meta_quality_checks IS 'Per-run data quality check results';

SELECT 'meta_quality_checks created' AS status;