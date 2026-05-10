"""
Seed dim_protocol with IANA-registered protocol numbers.
Includes only protocols likely to appear in network traffic.
"""
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimProtocol


PROTOCOLS = [
    {"protocol_num": 0,   "protocol_name": "HOPOPT",  "description": "IPv6 Hop-by-Hop Option"},
    {"protocol_num": 1,   "protocol_name": "ICMP",    "description": "Internet Control Message Protocol"},
    {"protocol_num": 2,   "protocol_name": "IGMP",    "description": "Internet Group Management Protocol"},
    {"protocol_num": 6,   "protocol_name": "TCP",     "description": "Transmission Control Protocol"},
    {"protocol_num": 17,  "protocol_name": "UDP",     "description": "User Datagram Protocol"},
    {"protocol_num": 41,  "protocol_name": "IPv6",    "description": "IPv6 encapsulation"},
    {"protocol_num": 47,  "protocol_name": "GRE",     "description": "Generic Routing Encapsulation"},
    {"protocol_num": 50,  "protocol_name": "ESP",     "description": "IPsec Encapsulating Security Payload"},
    {"protocol_num": 51,  "protocol_name": "AH",      "description": "IPsec Authentication Header"},
    {"protocol_num": 58,  "protocol_name": "ICMPv6",  "description": "ICMP for IPv6"},
    {"protocol_num": 89,  "protocol_name": "OSPF",    "description": "Open Shortest Path First"},
    {"protocol_num": 132, "protocol_name": "SCTP",    "description": "Stream Control Transmission Protocol"},
]


def seed():
    """Populate dim_protocol. Idempotent."""
    with get_session() as session:
        existing = session.scalar(select(DimProtocol).limit(1))
        if existing:
            count = session.query(DimProtocol).count()
            print(f"  ⏭️  dim_protocol already has {count} rows — skipping")
            return

        session.bulk_insert_mappings(DimProtocol, PROTOCOLS)
        print(f"  ✅ dim_protocol: inserted {len(PROTOCOLS)} rows")


if __name__ == "__main__":
    seed()