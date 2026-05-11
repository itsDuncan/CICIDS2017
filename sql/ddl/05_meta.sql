-- =====================================================================
-- SOC SENTINEL — META TABLES
-- File: sql/ddl/05_meta.sql
-- Purpose: ETL pipeline observability and lineage tracking
-- =====================================================================

SET search_path TO warehouse, public;

-- ---------------------------------------------------------------------
-- meta_pipeline_runs — Track every ETL pipeline execution
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.meta_pipeline_runs CASCADE;
CREATE TABLE warehouse.meta_pipeline_runs (
    run_id              BIGSERIAL PRIMARY KEY,
    pipeline_name       VARCHAR(50) NOT NULL,
    source_system       VARCHAR(20) NOT NULL,
    run_mode            VARCHAR(20) NOT NULL,         -- 'full', 'incremental', 'sample'
    started_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMP,
    duration_seconds    NUMERIC(10, 2),
    status              VARCHAR(20) NOT NULL DEFAULT 'running',  -- 'running', 'success', 'failed'
    rows_extracted      BIGINT,
    rows_transformed    BIGINT,
    rows_enriched       BIGINT,
    rows_loaded         BIGINT,
    error_message       TEXT,
    config_json         TEXT
);

CREATE INDEX idx_meta_pipeline_status ON warehouse.meta_pipeline_runs(status);
CREATE INDEX idx_meta_pipeline_started ON warehouse.meta_pipeline_runs(started_at DESC);

COMMENT ON TABLE warehouse.meta_pipeline_runs IS 'Audit log for every ETL pipeline execution';

-- ---------------------------------------------------------------------
-- meta_pipeline_stages — Track each stage within a run
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS warehouse.meta_pipeline_stages CASCADE;
CREATE TABLE warehouse.meta_pipeline_stages (
    stage_id            BIGSERIAL PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES warehouse.meta_pipeline_runs(run_id),
    stage_name          VARCHAR(50) NOT NULL,         -- 'extract', 'transform', 'enrich', 'load', 'quality'
    started_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMP,
    duration_seconds    NUMERIC(10, 2),
    status              VARCHAR(20) NOT NULL DEFAULT 'running',
    rows_in             BIGINT,
    rows_out            BIGINT,
    notes               TEXT,
    error_message       TEXT
);

CREATE INDEX idx_meta_stage_run ON warehouse.meta_pipeline_stages(run_id);

COMMENT ON TABLE warehouse.meta_pipeline_stages IS 'Per-stage timing and row counts for ETL runs';

-- =====================================================================
-- VERIFICATION
-- =====================================================================
SELECT
    table_name,
    (SELECT count(*) FROM information_schema.columns
     WHERE table_schema = 'warehouse' AND table_name = t.table_name) AS column_count
FROM information_schema.tables t
WHERE table_schema = 'warehouse'
  AND table_name LIKE 'meta_%'
ORDER BY table_name;

-- Expected: 2 rows (meta_pipeline_runs, meta_pipeline_stages)