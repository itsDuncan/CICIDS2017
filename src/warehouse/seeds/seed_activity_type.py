"""
Seed dim_activity_type with all CERT r4.2 activity types we observed.
Risk weights are baseline values used in Phase 2 risk scoring before ML adjusts them.
"""
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimActivityType


ACTIVITY_TYPES = [
    {
        "activity_name": "Logon",
        "activity_category": "authentication",
        "risk_weight": 1.0,
        "description": "User logged into a system. Baseline activity.",
    },
    {
        "activity_name": "Logoff",
        "activity_category": "authentication",
        "risk_weight": 1.0,
        "description": "User logged off a system. Baseline activity.",
    },
    {
        "activity_name": "Connect",
        "activity_category": "device",
        "risk_weight": 3.0,
        "description": "USB or removable storage device connected. Higher baseline risk for insider scenarios.",
    },
    {
        "activity_name": "Disconnect",
        "activity_category": "device",
        "risk_weight": 1.5,
        "description": "USB or removable storage device disconnected.",
    },
    {
        "activity_name": "File Access",
        "activity_category": "file",
        "risk_weight": 1.5,
        "description": "User accessed a file on a system. Risk varies with file type and after-hours flag.",
    },
    {
        "activity_name": "Email Send",
        "activity_category": "email",
        "risk_weight": 1.5,
        "description": "Email sent. Risk increases with external recipients, attachments, or unusual volume.",
    },
    # Reserved for Phase 2.5 (when http.csv is ingested)
    {
        "activity_name": "HTTP Visit",
        "activity_category": "web",
        "risk_weight": 1.0,
        "description": "User visited a web page. Risk varies with destination and after-hours context.",
    },
]


def seed():
    """Populate dim_activity_type. Idempotent."""
    with get_session() as session:
        existing = session.scalar(select(DimActivityType).limit(1))
        if existing:
            count = session.query(DimActivityType).count()
            print(f"  ⏭️  dim_activity_type already has {count} rows — skipping")
            return

        session.bulk_insert_mappings(DimActivityType, ACTIVITY_TYPES)
        print(f"  ✅ dim_activity_type: inserted {len(ACTIVITY_TYPES)} rows")


if __name__ == "__main__":
    seed()