"""
Pipeline execution context.

A single object passed between stages, carrying configuration, intermediate
data, and metrics. Avoids global state and makes testing trivial.
"""
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class PipelineContext:
    """Shared state for a single pipeline run."""

    # Configuration
    pipeline_name: str = "cicids_to_warehouse"
    source_system: str = "CICIDS"
    run_mode: str = "full"                          # 'full', 'sample', 'test'
    sample_size: Optional[int] = None               # None = all rows
    truncate_facts: bool = True                     # full reload mode

    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    input_parquet: Optional[Path] = None
    log_dir: Optional[Path] = None

    # Run tracking
    run_id: Optional[int] = None
    started_at: datetime = field(default_factory=datetime.now)

    # Stage outputs (passed forward)
    extracted_df: Any = None                        # Pandas DataFrame
    transformed_df: Any = None
    enriched_ip_data: dict = field(default_factory=dict)

    # Metrics (populated by stages)
    rows_extracted: int = 0
    rows_transformed: int = 0
    rows_enriched: int = 0
    rows_loaded: int = 0

    def __post_init__(self):
        """Resolve paths relative to project root."""
        if self.input_parquet is None:
            self.input_parquet = self.project_root / "data" / "interim" / "cicids_clean.parquet"
        if self.log_dir is None:
            self.log_dir = self.project_root / "logs"
            self.log_dir.mkdir(parents=True, exist_ok=True)

    def summary(self) -> dict:
        """Return a serializable summary of the run."""
        return {
            "pipeline_name": self.pipeline_name,
            "source_system": self.source_system,
            "run_mode": self.run_mode,
            "sample_size": self.sample_size,
            "rows_extracted": self.rows_extracted,
            "rows_transformed": self.rows_transformed,
            "rows_enriched": self.rows_enriched,
            "rows_loaded": self.rows_loaded,
        }