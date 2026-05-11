"""
SOC Sentinel ETL pipeline orchestrator.

Runs the full extract → transform → enrich → load sequence with audit logging.

Usage:
    python -m src.etl.pipeline --mode full
    python -m src.etl.pipeline --mode sample --sample-size 10000
    python -m src.etl.pipeline --mode sample --skip-enrich  # skip API calls
"""
import argparse
import sys
import time
from pathlib import Path

from src.etl.context import PipelineContext
from src.etl.logger import get_logger
from src.etl.run_tracker import PipelineRun
from src.etl import extract, transform, enrich, load, quality

logger = get_logger("pipeline")


# ---------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="SOC Sentinel ETL pipeline — CICIDS2017 to PostgreSQL warehouse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Run with full dataset (~12 minutes):
    python -m src.etl.pipeline --mode full

  Run with a 10K-row sample (~2 minutes):
    python -m src.etl.pipeline --mode sample --sample-size 10000

  Run without external API enrichment (faster, no quota use):
    python -m src.etl.pipeline --mode sample --skip-enrich

  Run without truncating fact table (append mode):
    python -m src.etl.pipeline --mode sample --no-truncate
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["full", "sample"],
        default="sample",
        help="Pipeline run mode (default: sample)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=10_000,
        help="Sample size when --mode=sample (default: 10000)",
    )
    parser.add_argument(
        "--skip-enrich",
        action="store_true",
        help="Skip enrich stage (no external API calls)",
    )
    parser.add_argument(
        "--no-truncate",
        action="store_true",
        help="Append to fact_security_event instead of TRUNCATE (default: truncate)",
    )
    parser.add_argument(
        "--input-parquet",
        type=str,
        default=None,
        help="Override input parquet path (default: data/interim/cicids_clean.parquet)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------
# Pipeline execution
# ---------------------------------------------------------------------

def run_pipeline(ctx: PipelineContext, skip_enrich: bool = False) -> dict:
    """
    Execute the full pipeline. Returns a result dict with timing and counts.
    Each stage is wrapped in audit logging via PipelineRun/PipelineStage.
    """
    start = time.time()

    with PipelineRun(ctx) as run:
        # ----- EXTRACT -----
        with run.stage("extract") as stage:
            extract.run(ctx)
            stage.set_metrics(rows_in=0, rows_out=ctx.rows_extracted)

        # ----- TRANSFORM -----
        with run.stage("transform") as stage:
            transform.run(ctx)
            stage.set_metrics(rows_in=ctx.rows_extracted, rows_out=ctx.rows_transformed)

        # ----- ENRICH (optional) -----
        if skip_enrich:
            logger.info("⏭️  Skipping enrich stage (--skip-enrich)")
            ctx.enriched_ip_data = {}
        else:
            with run.stage("enrich") as stage:
                enrich.run(ctx)
                stage.set_metrics(rows_in=ctx.rows_transformed, rows_out=ctx.rows_enriched)

        # ----- LOAD -----
        with run.stage("load") as stage:
            loaded = load.run(ctx)
            stage.set_metrics(rows_in=ctx.rows_transformed, rows_out=loaded)

        # ----- QUALITY -----
        with run.stage("quality") as stage:
            report = quality.run(ctx)
            stage.set_metrics(
                rows_in=len(report.results),
                rows_out=report.passed_count,
                notes=f"passed={report.passed_count}, warnings={report.warning_count}, errors={report.error_count}",
            )
            if report.error_count > 0:
                logger.error(
                    f"Quality checks found {report.error_count} ERRORS — "
                    f"see warehouse.meta_quality_checks for details"
                )

    elapsed = time.time() - start
    return {
        "run_id": ctx.run_id,
        "elapsed_seconds": elapsed,
        "rows_extracted": ctx.rows_extracted,
        "rows_transformed": ctx.rows_transformed,
        "rows_enriched": ctx.rows_enriched,
        "rows_loaded": ctx.rows_loaded,
        "skipped_enrich": skip_enrich,
    }


# ---------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------

def print_summary(result: dict) -> None:
    """Pretty-print the final result."""
    print()
    print("=" * 60)
    print("PIPELINE RUN SUMMARY")
    print("=" * 60)
    print(f"  Run ID:           {result['run_id']}")
    print(f"  Duration:         {result['elapsed_seconds']:.1f}s")
    print(f"  Rows extracted:   {result['rows_extracted']:,}")
    print(f"  Rows transformed: {result['rows_transformed']:,}")
    print(f"  IPs enriched:     {result['rows_enriched']:,}")
    print(f"  Rows loaded:      {result['rows_loaded']:,}")
    if result["skipped_enrich"]:
        print(f"  ⚠️  Enrichment was skipped")
    print(f"  Throughput:       {result['rows_loaded'] / max(result['elapsed_seconds'], 0.001):,.0f} rows/sec")
    print("=" * 60)


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    args = parse_args(argv)

    # Build context from CLI args
    ctx = PipelineContext(
        run_mode=args.mode,
        sample_size=args.sample_size if args.mode == "sample" else None,
        truncate_facts=not args.no_truncate,
    )

    if args.input_parquet:
        ctx.input_parquet = Path(args.input_parquet).resolve()

    logger.info(f"Starting pipeline: mode={args.mode}, "
                f"sample_size={args.sample_size if args.mode == 'sample' else 'N/A'}, "
                f"skip_enrich={args.skip_enrich}, "
                f"truncate={ctx.truncate_facts}")

    try:
        result = run_pipeline(ctx, skip_enrich=args.skip_enrich)
        print_summary(result)
        return 0
    except KeyboardInterrupt:
        logger.error("Pipeline interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Pipeline failed: {e}")
        print()
        print("=" * 60)
        print(f"❌ PIPELINE FAILED: {e}")
        print("=" * 60)
        print("\nTroubleshooting:")
        print("  - Check logs/ for the full traceback")
        print("  - Check warehouse.meta_pipeline_runs for the failed run record")
        print("  - For DB connection issues, verify .env is set up correctly")
        return 1


if __name__ == "__main__":
    sys.exit(main())