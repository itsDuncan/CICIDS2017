"""
Seed dim_time with 1,440 minute-of-day rows.
Covers every (hour, minute) pair from 00:00 to 23:59.
"""
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimTime


def classify_day_part(hour: int) -> str:
    """Categorize hour into a day-part bucket."""
    if 0 <= hour < 5:
        return "late_night"
    if 5 <= hour < 8:
        return "early_morning"
    if 8 <= hour < 12:
        return "morning"
    if 12 <= hour < 17:
        return "afternoon"
    if 17 <= hour < 20:
        return "evening"
    return "night"  # 20-23


def is_business_hour(hour: int) -> int:
    """1 if hour is within typical business hours (8am-5pm)."""
    return 1 if 8 <= hour < 17 else 0


def is_after_hours(hour: int) -> int:
    """1 if hour is OUTSIDE 7am-7pm (key insider threat feature)."""
    return 1 if hour < 7 or hour >= 19 else 0


def build_time_row(hour: int, minute: int) -> dict:
    """Build a single dim_time row."""
    time_sk = hour * 60 + minute  # 0..1439

    if hour == 0:
        h12, ampm = 12, "AM"
    elif hour < 12:
        h12, ampm = hour, "AM"
    elif hour == 12:
        h12, ampm = 12, "PM"
    else:
        h12, ampm = hour - 12, "PM"

    return {
        "time_sk": time_sk,
        "hour_24": hour,
        "minute": minute,
        "hour_12": h12,
        "am_pm": ampm,
        "day_part": classify_day_part(hour),
        "is_business_hour": is_business_hour(hour),
        "is_after_hours": is_after_hours(hour),
    }


def seed():
    """Populate dim_time. Idempotent."""
    with get_session() as session:
        existing = session.scalar(select(DimTime).limit(1))
        if existing:
            count = session.query(DimTime).count()
            print(f"  ⏭️  dim_time already has {count:,} rows — skipping")
            return

        rows = [build_time_row(h, m) for h in range(24) for m in range(60)]
        session.bulk_insert_mappings(DimTime, rows)
        print(f"  ✅ dim_time: inserted {len(rows):,} rows (1-minute granularity)")


if __name__ == "__main__":
    seed()