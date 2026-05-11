"""
Data quality module — automated post-load checks.

Validates that the warehouse matches expected invariants after every ETL run.
Each check writes to warehouse.meta_quality_checks with pass/fail status.

Categories:
    row_count    — fact row counts match upstream expectations
    fk_integrity — every FK resolves to a real dimension row
    distribution — attack family/family ratios are plausible
    temporal     — attack windows match CICIDS2017 documentation
    enrichment   — external IP geo coverage is acceptable
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import pandas as pd
from sqlalchemy import text

from src.etl.context import PipelineContext
from src.etl.logger import get_logger
from src.warehouse import get_engine

logger = get_logger("quality")


# ---------------------------------------------------------------------
# Check result data structure
# ---------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    category: str
    severity: str            # 'info', 'warning', 'error'
    passed: bool
    expected: str = ""
    actual: str = ""
    message: str = ""


@dataclass
class QualityReport:
    run_id: Optional[int] = None
    results: list[CheckResult] = field(default_factory=list)

    @property
    def passed_count(self):
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self):
        return sum(1 for r in self.results if not r.passed)

    @property
    def error_count(self):
        return sum(1 for r in self.results if not r.passed and r.severity == "error")

    @property
    def warning_count(self):
        return sum(1 for r in self.results if not r.passed and r.severity == "warning")


# ---------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------

def check_fact_row_count(ctx: PipelineContext) -> CheckResult:
    """Fact table row count matches what was loaded."""
    engine = get_engine()
    with engine.connect() as conn:
        actual = conn.execute(
            text("SELECT COUNT(*) FROM warehouse.fact_security_event")
        ).scalar()
    expected = ctx.rows_loaded
    return CheckResult(
        name="fact_row_count_matches_loaded",
        category="row_count",
        severity="error",
        passed=(actual == expected),
        expected=str(expected),
        actual=str(actual),
        message=f"Fact table has {actual:,} rows; loader reported {expected:,}",
    )


def check_fk_integrity_assets() -> CheckResult:
    """Every src/dest asset FK should point to a real dim_asset row."""
    engine = get_engine()
    with engine.connect() as conn:
        orphans = conn.execute(text("""
            SELECT COUNT(*) FROM warehouse.fact_security_event f
            LEFT JOIN warehouse.dim_asset s ON f.src_asset_sk = s.asset_sk
            LEFT JOIN warehouse.dim_asset d ON f.dest_asset_sk = d.asset_sk
            WHERE (f.src_asset_sk IS NOT NULL AND s.asset_sk IS NULL)
               OR (f.dest_asset_sk IS NOT NULL AND d.asset_sk IS NULL)
        """)).scalar()
    return CheckResult(
        name="fk_integrity_assets",
        category="fk_integrity",
        severity="error",
        passed=(orphans == 0),
        expected="0",
        actual=str(orphans),
        message=f"{orphans} fact rows have orphaned src/dest asset FKs",
    )


def check_fk_integrity_attack_type() -> CheckResult:
    """Every attack_sk should resolve to a real dim_attack_type row."""
    engine = get_engine()
    with engine.connect() as conn:
        orphans = conn.execute(text("""
            SELECT COUNT(*) FROM warehouse.fact_security_event f
            LEFT JOIN warehouse.dim_attack_type a ON f.attack_sk = a.attack_sk
            WHERE f.attack_sk IS NOT NULL AND a.attack_sk IS NULL
        """)).scalar()
    return CheckResult(
        name="fk_integrity_attack_type",
        category="fk_integrity",
        severity="error",
        passed=(orphans == 0),
        expected="0",
        actual=str(orphans),
        message=f"{orphans} fact rows have orphaned attack_sk FKs",
    )


def check_fk_integrity_dates() -> CheckResult:
    """Every date_sk should resolve to dim_date."""
    engine = get_engine()
    with engine.connect() as conn:
        orphans = conn.execute(text("""
            SELECT COUNT(*) FROM warehouse.fact_security_event f
            LEFT JOIN warehouse.dim_date d ON f.date_sk = d.date_sk
            WHERE d.date_sk IS NULL
        """)).scalar()
    return CheckResult(
        name="fk_integrity_dates",
        category="fk_integrity",
        severity="error",
        passed=(orphans == 0),
        expected="0",
        actual=str(orphans),
        message=f"{orphans} fact rows have date_sk values not in dim_date",
    )


def check_attack_distribution() -> CheckResult:
    """Class balance is realistic: 50-95% Benign for CICIDS2017."""
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                ROUND(100.0 * SUM(CASE WHEN attack_family_denorm = 'Benign' THEN 1 ELSE 0 END)
                          / NULLIF(COUNT(*), 0), 2) AS benign_pct,
                COUNT(*) AS total
            FROM warehouse.fact_security_event
        """)).fetchone()
    benign_pct = float(result[0]) if result[0] else 0.0
    total = result[1]

    # Skip if empty or tiny sample
    if total < 100:
        return CheckResult(
            name="attack_distribution_benign_ratio",
            category="distribution",
            severity="info",
            passed=True,
            expected="50-95% Benign",
            actual=f"{benign_pct}% ({total} rows — too small to evaluate)",
            message="Skipped: dataset too small",
        )

    in_range = 50.0 <= benign_pct <= 95.0
    return CheckResult(
        name="attack_distribution_benign_ratio",
        category="distribution",
        severity="warning",
        passed=in_range,
        expected="50-95%",
        actual=f"{benign_pct}%",
        message=f"Benign class is {benign_pct}% of {total:,} rows",
    )


def check_heartbleed_window() -> CheckResult:
    """Heartbleed should be on Wed 2017-07-05 between 15:00-16:00."""
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT MIN(f.event_time)::TEXT AS first_seen,
                   MAX(f.event_time)::TEXT AS last_seen,
                   COUNT(*) AS events
            FROM warehouse.fact_security_event f
            JOIN warehouse.dim_attack_type a ON f.attack_sk = a.attack_sk
            WHERE a.attack_label = 'Heartbleed'
        """)).fetchone()
    first, last, count = result

    if count == 0:
        return CheckResult(
            name="heartbleed_window_matches_documentation",
            category="temporal",
            severity="info",
            passed=True,
            expected="11 events on Wed 2017-07-05 15:12-15:32",
            actual="No Heartbleed events present",
            message="Skipped: no Heartbleed events in current data",
        )

    expected_date = "2017-07-05"
    correct_date = first.startswith(expected_date) and last.startswith(expected_date)
    correct_hour = " 15:" in first  # 15:xx start time

    return CheckResult(
        name="heartbleed_window_matches_documentation",
        category="temporal",
        severity="error",
        passed=(correct_date and correct_hour),
        expected=f"Wed {expected_date} 15:12-15:32",
        actual=f"{first} to {last} ({count} events)",
        message="Heartbleed events outside documented window" if not (correct_date and correct_hour) else "OK",
    )


def check_external_ip_geo_coverage() -> CheckResult:
    """External IPs should have >= 80% country coverage."""
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                COUNT(*) AS total,
                COUNT(country_iso) AS with_country,
                ROUND(100.0 * COUNT(country_iso) / NULLIF(COUNT(*), 0), 2) AS pct
            FROM warehouse.dim_asset
            WHERE is_internal = 0
        """)).fetchone()
    total, with_country, pct = result

    if total == 0:
        return CheckResult(
            name="external_ip_geo_coverage",
            category="enrichment",
            severity="info",
            passed=True,
            expected=">=80%",
            actual="0 external IPs",
            message="No external IPs to check",
        )

    return CheckResult(
        name="external_ip_geo_coverage",
        category="enrichment",
        severity="warning",
        passed=(float(pct or 0) >= 80.0),
        expected=">=80%",
        actual=f"{pct}% ({with_country}/{total})",
        message=f"GeoIP resolution for external IPs",
    )


def check_dim_user_population() -> CheckResult:
    """dim_user is empty in Phase 1 (CERT not loaded yet) — informational."""
    engine = get_engine()
    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM warehouse.dim_user")
        ).scalar()
    return CheckResult(
        name="dim_user_phase1_expectation",
        category="row_count",
        severity="info",
        passed=True,  # always pass — informational
        expected="0 in Phase 1, ~16,743 after CERT ETL",
        actual=str(count),
        message=f"dim_user has {count} rows (expected for current phase)",
    )


# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

def save_results(report: QualityReport) -> None:
    """Write all check results to meta_quality_checks."""
    if not report.results:
        return
    engine = get_engine()
    with engine.begin() as conn:
        for r in report.results:
            conn.execute(text("""
                INSERT INTO warehouse.meta_quality_checks
                    (run_id, check_name, check_category, severity,
                     passed, expected_value, actual_value, message)
                VALUES
                    (:run_id, :name, :category, :severity,
                     :passed, :expected, :actual, :message)
            """), {
                "run_id": report.run_id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity,
                "passed": 1 if r.passed else 0,
                "expected": r.expected,
                "actual": r.actual,
                "message": r.message,
            })


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

def run(ctx: Optional[PipelineContext] = None) -> QualityReport:
    """
    Execute all data quality checks. Logs results and persists them.

    Can be called standalone (ctx=None) or as part of the pipeline.
    """
    report = QualityReport(run_id=ctx.run_id if ctx else None)

    checks = [
        ("Fact row count", lambda: check_fact_row_count(ctx) if ctx else None),
        ("FK integrity (assets)", check_fk_integrity_assets),
        ("FK integrity (attack types)", check_fk_integrity_attack_type),
        ("FK integrity (dates)", check_fk_integrity_dates),
        ("Attack distribution", check_attack_distribution),
        ("Heartbleed window", check_heartbleed_window),
        ("External IP geo coverage", check_external_ip_geo_coverage),
        ("dim_user phase 1", check_dim_user_population),
    ]

    logger.info(f"Running {len(checks)} quality checks")
    for label, fn in checks:
        try:
            result = fn()
            if result is None:
                continue
            report.results.append(result)
            icon = "✓" if result.passed else "✗" if result.severity == "error" else "⚠"
            logger.info(f"  {icon} {result.name}: expected={result.expected}, actual={result.actual}")
        except Exception as e:
            logger.error(f"Check '{label}' raised exception: {e}")
            report.results.append(CheckResult(
                name=label,
                category="execution_error",
                severity="error",
                passed=False,
                message=f"Exception: {e}",
            ))

    save_results(report)

    # Summary
    logger.info(
        f"Quality checks: {report.passed_count} passed, "
        f"{report.warning_count} warnings, {report.error_count} errors"
    )

    return report


if __name__ == "__main__":
    # Standalone invocation — no pipeline context
    report = run()
    print(f"\nPassed: {report.passed_count} / {len(report.results)}")
    print(f"Warnings: {report.warning_count}")
    print(f"Errors: {report.error_count}")
    if report.failed_count > 0:
        print("\nFailures:")
        for r in report.results:
            if not r.passed:
                print(f"  ✗ [{r.severity}] {r.name}: expected={r.expected}, actual={r.actual}")
    exit(1 if report.error_count > 0 else 0)