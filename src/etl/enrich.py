"""
Enrich stage — add geographic and reputation context to external IPs.

GeoIP enrichment via MaxMind GeoLite2-City.mmdb (local lookup, no API).
Reputation enrichment via AbuseIPDB API (rate-limited, top-N only).

Both enrichments populate ctx.enriched_ip_data as a dict keyed by IP:
    {
        '205.174.165.73': {
            'country_iso': 'CA',
            'country_name': 'Canada',
            'city': 'Halifax',
            'latitude': 44.6488,
            'longitude': -63.5752,
            'asn': 11260,
            'asn_org': 'EastLink',
            'abuse_confidence': 87,
            'is_known_attacker': 1
        },
        ...
    }
"""
import os
import time
from pathlib import Path
from typing import Optional

import geoip2.database
import geoip2.errors
import pandas as pd
import requests
from dotenv import load_dotenv

from src.etl.context import PipelineContext
from src.etl.logger import get_logger

logger = get_logger("enrich")


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_DAILY_LIMIT = 1000          # Free tier cap
ABUSEIPDB_TOP_N_ENRICH = 500          # Stay well under the daily limit
ABUSEIPDB_TIMEOUT_SEC = 10
ABUSEIPDB_THROTTLE_SEC = 0.1          # 10 req/sec is well within rate limit

ENRICHMENT_CACHE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data" / "interim" / "enrichment_cache.parquet"
)

def _load_env():
    """Load .env from project root."""
    project_root = Path(__file__).resolve().parents[2]
    load_dotenv(project_root / ".env")


def _resolve_mmdb_path() -> Path:
    """Resolve MaxMind path from .env, handling both absolute and relative."""
    _load_env()
    project_root = Path(__file__).resolve().parents[2]
    raw = os.getenv("MAXMIND_DB_PATH")
    if not raw:
        raise RuntimeError("MAXMIND_DB_PATH not set in .env")
    path = Path(raw)
    if not path.is_absolute():
        path = project_root / path
    if not path.exists():
        raise FileNotFoundError(f"MaxMind .mmdb not found at {path}")
    return path


# ---------------------------------------------------------------------
# MaxMind GeoIP enrichment
# ---------------------------------------------------------------------

def enrich_geo(external_ips: list[str]) -> dict[str, dict]:
    """
    Look up geographic data for a list of IPs using MaxMind GeoLite2.

    Returns a dict mapping each IP to its geo attributes. IPs that can't
    be resolved get an entry with NaN values (logged but not raised).
    """
    mmdb_path = _resolve_mmdb_path()
    logger.info(f"Opening MaxMind DB: {mmdb_path.name}")

    results = {}
    success = 0
    miss = 0
    error = 0

    with geoip2.database.Reader(str(mmdb_path)) as reader:
        for ip in external_ips:
            try:
                r = reader.city(ip)
                results[ip] = {
                    "country_iso": r.country.iso_code,
                    "country_name": r.country.name,
                    "city": r.city.name,
                    "latitude": float(r.location.latitude) if r.location.latitude else None,
                    "longitude": float(r.location.longitude) if r.location.longitude else None,
                    "asn": None,        # GeoLite2-City doesn't include ASN
                    "asn_org": None,    # would need GeoLite2-ASN (separate file)
                }
                success += 1
            except geoip2.errors.AddressNotFoundError:
                results[ip] = {
                    "country_iso": None, "country_name": None, "city": None,
                    "latitude": None, "longitude": None, "asn": None, "asn_org": None,
                }
                miss += 1
            except Exception as e:
                logger.debug(f"GeoIP error for {ip}: {e}")
                results[ip] = {
                    "country_iso": None, "country_name": None, "city": None,
                    "latitude": None, "longitude": None, "asn": None, "asn_org": None,
                }
                error += 1

    logger.info(f"GeoIP: {success:,} resolved, {miss:,} not-found, {error:,} errors")
    return results


# ---------------------------------------------------------------------
# AbuseIPDB reputation enrichment
# ---------------------------------------------------------------------

def _check_one_ip(api_key: str, ip: str, session: requests.Session) -> Optional[dict]:
    """Query AbuseIPDB for one IP. Returns None on error."""
    try:
        resp = session.get(
            ABUSEIPDB_API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=ABUSEIPDB_TIMEOUT_SEC,
        )
        if resp.status_code == 429:
            logger.warning(f"AbuseIPDB rate-limit hit at {ip} — stopping enrichment early")
            return "RATE_LIMITED"  # sentinel
        if resp.status_code != 200:
            logger.debug(f"AbuseIPDB {resp.status_code} for {ip}")
            return None
        data = resp.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "is_known_attacker": 1 if data.get("abuseConfidenceScore", 0) >= 50 else 0,
        }
    except Exception as e:
        logger.debug(f"AbuseIPDB exception for {ip}: {e}")
        return None


def enrich_reputation(
    top_n_ips: list[str],
    api_key: str,
) -> dict[str, dict]:
    """
    Look up reputation for the top-N most-active external IPs.

    Stops early if rate-limited. Returns partial results in that case.
    """
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY missing — skipping reputation enrichment")
        return {}

    if len(top_n_ips) > ABUSEIPDB_DAILY_LIMIT:
        logger.warning(
            f"Truncating from {len(top_n_ips)} to {ABUSEIPDB_DAILY_LIMIT} IPs "
            f"to respect free tier daily limit"
        )
        top_n_ips = top_n_ips[:ABUSEIPDB_DAILY_LIMIT]

    logger.info(f"Querying AbuseIPDB for {len(top_n_ips)} IPs (throttled to ~10 req/s)")

    results = {}
    rate_limited = False

    with requests.Session() as session:
        for i, ip in enumerate(top_n_ips, start=1):
            if rate_limited:
                break

            data = _check_one_ip(api_key, ip, session)
            if data == "RATE_LIMITED":
                rate_limited = True
                break
            if data is not None:
                results[ip] = data

            time.sleep(ABUSEIPDB_THROTTLE_SEC)

            if i % 50 == 0:
                logger.info(f"  Progress: {i}/{len(top_n_ips)} IPs enriched")

    logger.info(f"AbuseIPDB: {len(results)} IPs enriched ({'partial' if rate_limited else 'complete'})")
    return results


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

def _load_cache() -> dict[str, dict]:
    """Load cached enrichment from parquet. Returns empty dict if no cache exists."""
    if not ENRICHMENT_CACHE_PATH.exists():
        return {}
    try:
        df = pd.read_parquet(ENRICHMENT_CACHE_PATH)
        cache = df.set_index("ip").to_dict(orient="index")
        logger.info(f"Loaded {len(cache):,} cached IPs from {ENRICHMENT_CACHE_PATH.name}")
        return cache
    except Exception as e:
        logger.warning(f"Could not load cache: {e} — starting fresh")
        return {}


def _save_cache(cache: dict[str, dict]) -> None:
    """Persist enrichment cache to parquet."""
    if not cache:
        return
    ENRICHMENT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame.from_dict(cache, orient="index").reset_index().rename(
        columns={"index": "ip"}
    )
    df.to_parquet(ENRICHMENT_CACHE_PATH, compression="zstd", index=False)
    logger.info(f"Saved {len(df):,} IPs to enrichment cache")

def run(ctx: PipelineContext) -> dict:
    """
    Enrich external IPs using a persistent cache to minimize API calls.

    Strategy:
      1. Load cache of previously-enriched IPs from parquet
      2. Identify cache misses needing fresh enrichment
      3. MaxMind: enrich all cache-miss IPs (free, unlimited)
      4. AbuseIPDB: enrich top-N cache-miss IPs only (quota-protected)
      5. Merge cache + new results, persist updated cache
    """
    if ctx.transformed_df is None:
        raise ValueError("ctx.transformed_df is None — run transform.run(ctx) first")

    df = ctx.transformed_df

    # --- Identify distinct external IPs ---
    external_src = df.loc[df["src_ip_class"] == "external", "src_ip"]
    external_dest = df.loc[df["dest_ip_class"] == "external", "dest_ip"]
    external_ips = pd.concat([external_src, external_dest]).drop_duplicates().tolist()
    logger.info(f"Found {len(external_ips):,} distinct external IPs to enrich")

    # --- Load cache ---
    cache = _load_cache()
    cached_ips = set(cache.keys())
    new_ips = [ip for ip in external_ips if ip not in cached_ips]
    logger.info(
        f"Cache: {len(cached_ips & set(external_ips)):,} hits, "
        f"{len(new_ips):,} misses"
    )

    # --- Geo enrichment (only on cache misses) ---
    if new_ips:
        geo_data = enrich_geo(new_ips)
    else:
        geo_data = {}
        logger.info("All external IPs cached — skipping GeoIP lookups")

    # --- Reputation enrichment (top-N of cache misses only) ---
    if new_ips:
        # Rank cache-miss IPs by volume so we enrich the most impactful ones
        ip_volume = (
            pd.concat([external_src, external_dest])
            .value_counts()
        )
        miss_ips_by_volume = [ip for ip in ip_volume.index if ip in set(new_ips)]
        top_n_ips = miss_ips_by_volume[:ABUSEIPDB_TOP_N_ENRICH]
        logger.info(
            f"Top {len(top_n_ips)} uncached IPs by volume "
            f"will be sent to AbuseIPDB"
        )
        _load_env()
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        rep_data = enrich_reputation(top_n_ips, api_key)
    else:
        rep_data = {}
        logger.info("All external IPs cached — skipping AbuseIPDB lookups (saved quota!)")

    # --- Merge new results into cache ---
    for ip in new_ips:
        cache[ip] = {
            "country_iso": None, "country_name": None, "city": None,
            "latitude": None, "longitude": None,
            "asn": None, "asn_org": None,
            "abuse_confidence": None, "is_known_attacker": 0,
        }
        cache[ip].update(geo_data.get(ip, {}))
        cache[ip].update(rep_data.get(ip, {}))

    # --- Persist updated cache ---
    _save_cache(cache)

    # --- Return only the IPs relevant to this run ---
    enriched = {ip: cache[ip] for ip in external_ips if ip in cache}
    ctx.enriched_ip_data = enriched
    ctx.rows_enriched = len(enriched)

    # Summary
    countries = pd.Series(
        [v.get("country_iso") for v in enriched.values()]
    ).value_counts().head(10)
    logger.info(f"Top 10 countries by IP count:\n{countries.to_dict()}")

    return enriched