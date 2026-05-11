"""
Pipeline run tracking — writes to warehouse.meta_pipeline_runs and meta_pipeline_stages.

Provides context managers for clean start/end semantics:

    with PipelineRun(ctx) as run:
        with run.stage("extract") as stage:
            stage.set_metrics(rows_in=0, rows_out=1000)
"""
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from sqlalchemy import text

from src.etl.context import PipelineContext
from src.etl.logger import get_logger
from src.warehouse import get_engine

logger = get_logger("tracker")


class PipelineStage:
    """Context manager for a single stage within a run."""

    def __init__(self, run_id: int, stage_name: str):
        self.run_id = run_id
        self.stage_name = stage_name
        self.stage_id: Optional[int] = None
        self.started_at = datetime.now()
        self.rows_in = 0
        self.rows_out = 0
        self.notes = ""

    def __enter__(self):
        with get_engine().begin() as conn:
            result = conn.execute(text("""
                INSERT INTO warehouse.meta_pipeline_stages
                    (run_id, stage_name, started_at, status)
                VALUES (:run_id, :stage_name, :started_at, 'running')
                RETURNING stage_id
            """), {
                "run_id": self.run_id,
                "stage_name": self.stage_name,
                "started_at": self.started_at,
            })
            self.stage_id = result.scalar()
        logger.info(f"▶ Starting stage: {self.stage_name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        completed_at = datetime.now()
        duration = (completed_at - self.started_at).total_seconds()
        status = "failed" if exc_type else "success"
        error_msg = str(exc_val) if exc_val else None

        with get_engine().begin() as conn:
            conn.execute(text("""
                UPDATE warehouse.meta_pipeline_stages
                SET completed_at = :completed_at,
                    duration_seconds = :duration,
                    status = :status,
                    rows_in = :rows_in,
                    rows_out = :rows_out,
                    notes = :notes,
                    error_message = :error
                WHERE stage_id = :stage_id
            """), {
                "completed_at": completed_at,
                "duration": round(duration, 2),
                "status": status,
                "rows_in": self.rows_in,
                "rows_out": self.rows_out,
                "notes": self.notes,
                "error": error_msg,
                "stage_id": self.stage_id,
            })

        if status == "success":
            logger.info(f"✓ Stage '{self.stage_name}' completed in {duration:.1f}s "
                        f"(rows: {self.rows_in:,} → {self.rows_out:,})")
        else:
            logger.error(f"✗ Stage '{self.stage_name}' failed after {duration:.1f}s: {error_msg}")
        return False  # don't suppress exceptions

    def set_metrics(self, rows_in: int = 0, rows_out: int = 0, notes: str = ""):
        """Update metrics — call before stage exits."""
        self.rows_in = rows_in
        self.rows_out = rows_out
        self.notes = notes


class PipelineRun:
    """Context manager for a full pipeline run."""

    def __init__(self, ctx: PipelineContext):
        self.ctx = ctx
        self.run_id: Optional[int] = None

    def __enter__(self):
        config = json.dumps(self.ctx.summary())
        with get_engine().begin() as conn:
            result = conn.execute(text("""
                INSERT INTO warehouse.meta_pipeline_runs
                    (pipeline_name, source_system, run_mode, started_at, status, config_json)
                VALUES (:name, :source, :mode, :started, 'running', :config)
                RETURNING run_id
            """), {
                "name": self.ctx.pipeline_name,
                "source": self.ctx.source_system,
                "mode": self.ctx.run_mode,
                "started": self.ctx.started_at,
                "config": config,
            })
            self.run_id = result.scalar()
            self.ctx.run_id = self.run_id
        logger.info(f"╔══ Pipeline run {self.run_id} started: "
                    f"{self.ctx.pipeline_name} ({self.ctx.run_mode}) ══╗")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        completed_at = datetime.now()
        duration = (completed_at - self.ctx.started_at).total_seconds()
        status = "failed" if exc_type else "success"
        error_msg = str(exc_val) if exc_val else None

        with get_engine().begin() as conn:
            conn.execute(text("""
                UPDATE warehouse.meta_pipeline_runs
                SET completed_at = :completed_at,
                    duration_seconds = :duration,
                    status = :status,
                    rows_extracted = :extracted,
                    rows_transformed = :transformed,
                    rows_enriched = :enriched,
                    rows_loaded = :loaded,
                    error_message = :error
                WHERE run_id = :run_id
            """), {
                "completed_at": completed_at,
                "duration": round(duration, 2),
                "status": status,
                "extracted": self.ctx.rows_extracted,
                "transformed": self.ctx.rows_transformed,
                "enriched": self.ctx.rows_enriched,
                "loaded": self.ctx.rows_loaded,
                "error": error_msg,
                "run_id": self.run_id,
            })

        if status == "success":
            logger.info(f"╚══ Pipeline run {self.run_id} SUCCESS in {duration:.1f}s ══╝")
        else:
            logger.error(f"╚══ Pipeline run {self.run_id} FAILED: {error_msg} ══╝")
        return False

    @contextmanager
    def stage(self, stage_name: str):
        """Open a stage context within this run."""
        with PipelineStage(self.run_id, stage_name) as s:
            yield s