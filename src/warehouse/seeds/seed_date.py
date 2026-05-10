"""
Seed dim_date with calendar dates from 2010-01-01 through 2017-12-31.
Coverage:
- 2010-01-02 to 2011-05-17: CERT r4.2 dataset window
- 2017-07-03 to 2017-07-07: CICIDS2017 dataset window
- Buffer years on either side for flexibility
"""
from datetime import date, timedelta
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimDate

START_DATE = date(2010, 1, 1)
END_DATE = date(2017, 12, 31)

DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]


def date_to_sk(d: date) -> int:
    """Convert a date to YYYYMMDD integer surrogate key."""
    return d.year * 10000 + d.month * 100 + d.day


def build_date_row(d: date) -> dict:
    """Build a single dim_date row from a date."""
    iso_weekday = d.isoweekday()  # 1=Monday, 7=Sunday
    return {
        "date_sk": date_to_sk(d),
        "full_date": d,
        "day_of_week": iso_weekday,
        "day_name": DAY_NAMES[iso_weekday - 1],
        "day_of_month": d.day,
        "day_of_year": d.timetuple().tm_yday,
        "week_of_year": d.isocalendar().week,
        "month_num": d.month,
        "month_name": MONTH_NAMES[d.month - 1],
        "quarter": (d.month - 1) // 3 + 1,
        "year": d.year,
        "is_weekend": 1 if iso_weekday >= 6 else 0,
        "is_business_day": 1 if iso_weekday <= 5 else 0,
        "holiday_flag": 0,  # Skipping holiday logic for now
    }


def seed():
    """Populate dim_date. Idempotent — skips if already seeded."""
    with get_session() as session:
        existing = session.scalar(select(DimDate).limit(1))
        if existing:
            count = session.query(DimDate).count()
            print(f"  ⏭️  dim_date already has {count:,} rows — skipping")
            return

        rows = []
        current = START_DATE
        while current <= END_DATE:
            rows.append(build_date_row(current))
            current += timedelta(days=1)

        session.bulk_insert_mappings(DimDate, rows)
        print(f"  ✅ dim_date: inserted {len(rows):,} rows ({START_DATE} to {END_DATE})")


if __name__ == "__main__":
    seed()