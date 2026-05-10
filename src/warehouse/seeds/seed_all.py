"""
Seed all static dimensions in the correct dependency order.

Usage:
    python -m src.warehouse.seeds.seed_all

This script is idempotent — safe to run multiple times. Each seed module
checks if data already exists and skips if so.
"""
from src.warehouse.seeds import (
    seed_date,
    seed_time,
    seed_protocol,
    seed_attack_type,
    seed_activity_type,
    seed_port,
)


def seed_all():
    """Run all seed modules in order."""
    print("=" * 60)
    print("SEEDING STATIC DIMENSIONS")
    print("=" * 60)

    seeders = [
        ("dim_date",          seed_date.seed),
        ("dim_time",          seed_time.seed),
        ("dim_protocol",      seed_protocol.seed),
        ("dim_attack_type",   seed_attack_type.seed),
        ("dim_activity_type", seed_activity_type.seed),
        ("dim_port",          seed_port.seed),
    ]

    for name, seeder in seeders:
        print(f"\n→ {name}")
        try:
            seeder()
        except Exception as e:
            print(f"  ❌ Error seeding {name}: {e}")
            raise

    print("\n" + "=" * 60)
    print("✅ ALL DIMENSIONS SEEDED")
    print("=" * 60)


if __name__ == "__main__":
    seed_all()