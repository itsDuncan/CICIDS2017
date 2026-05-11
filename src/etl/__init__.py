"""
ETL pipeline for the SOC Sentinel warehouse.

Architecture:
    extract → transform → enrich → load → quality

Each module exposes a `run(...)` function that takes context and returns a result dict.
The pipeline orchestrator (src/etl/pipeline.py) chains them and logs to meta tables.
"""