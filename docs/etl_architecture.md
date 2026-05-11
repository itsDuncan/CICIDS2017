┌─────────────────────────────────────────────────────────────┐
│                  CLI ENTRY POINT                            │
│         python -m src.etl.pipeline --source cicids          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  PIPELINE ORCHESTRATOR                      │
│  (src/etl/pipeline.py)                                      │
│  Executes stages in order, logs to meta_pipeline_runs       │
│  Catches failures, supports --resume from last good stage   │
└──────────────────────────┬──────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
┌─────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  EXTRACT    │  │    TRANSFORM     │  │     ENRICH       │
│ extract.py  │─▶│  transform.py    │─▶│   enrich.py      │
│             │  │                  │  │                  │
│ Read clean  │  │ Feature eng.     │  │ MaxMind GeoIP    │
│ parquet     │  │ IP classify      │  │ AbuseIPDB        │
│ Sample/full │  │ Type coerce      │  │ Top-N enrich     │
└─────────────┘  └──────────────────┘  └────────┬─────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────┐
│                       LOAD                                  │
│                    load.py                                  │
│  1. Resolve surrogate keys against seeded dimensions        │
│  2. UPSERT new dim_asset rows (CICIDS IPs + enrichment)     │
│  3. UPSERT new dim_port rows (observed ports)               │
│  4. Bulk COPY fact rows into fact_security_event            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              QUALITY CHECKS (quality.py)                    │
│  Row count reconciliation · null checks · FK integrity      │
│  date range validation · attack distribution sanity         │
└─────────────────────────────────────────────────────────────┘