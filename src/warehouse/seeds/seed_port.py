"""
Seed dim_port with well-known service ports that may appear in CICIDS2017 traffic.
Ports actually observed in data will be added during Week 3 ETL.
"""
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimPort


WELL_KNOWN_PORTS = [
    # Web
    (80,    "HTTP",          "web",            "Standard HTTP web traffic"),
    (443,   "HTTPS",         "web",            "HTTP over TLS/SSL"),
    (8080,  "HTTP-Alt",      "web",            "Alternate HTTP — often used for proxies and botnet C2"),
    (8443,  "HTTPS-Alt",     "web",            "Alternate HTTPS"),
    (8088,  "HTTP-Alt2",     "web",            "Alternate HTTP — observed in CICIDS reconnaissance"),
    # Email
    (25,    "SMTP",          "mail",           "Simple Mail Transfer Protocol"),
    (110,   "POP3",          "mail",           "Post Office Protocol v3"),
    (143,   "IMAP",          "mail",           "Internet Message Access Protocol"),
    (465,   "SMTPS",         "mail",           "SMTP over TLS"),
    (587,   "SMTP-Submit",   "mail",           "SMTP message submission"),
    (993,   "IMAPS",         "mail",           "IMAP over TLS"),
    (995,   "POP3S",         "mail",           "POP3 over TLS"),
    # Remote access
    (22,    "SSH",           "remote_access",  "Secure Shell — frequent brute-force target"),
    (23,    "Telnet",        "remote_access",  "Cleartext remote shell — deprecated but still attacked"),
    (3389,  "RDP",           "remote_access",  "Microsoft Remote Desktop Protocol"),
    (5900,  "VNC",           "remote_access",  "Virtual Network Computing"),
    # File transfer
    (20,    "FTP-Data",      "file_transfer",  "FTP data channel"),
    (21,    "FTP-Control",   "file_transfer",  "FTP control channel — frequent brute-force target"),
    (69,    "TFTP",          "file_transfer",  "Trivial File Transfer Protocol"),
    (115,   "SFTP",          "file_transfer",  "Simple File Transfer Protocol"),
    (445,   "SMB",           "file_transfer",  "Server Message Block — Windows file sharing"),
    (139,   "NetBIOS-SSN",   "file_transfer",  "NetBIOS session — Windows networking"),
    # DNS / network services
    (53,    "DNS",           "network_service","Domain Name System"),
    (67,    "DHCP-Server",   "network_service","DHCP server"),
    (68,    "DHCP-Client",   "network_service","DHCP client"),
    (123,   "NTP",           "network_service","Network Time Protocol"),
    (161,   "SNMP",          "network_service","Simple Network Management Protocol"),
    (162,   "SNMP-Trap",     "network_service","SNMP trap"),
    # Database
    (1433,  "MSSQL",         "database",       "Microsoft SQL Server"),
    (1521,  "Oracle",        "database",       "Oracle DB listener"),
    (3306,  "MySQL",         "database",       "MySQL/MariaDB"),
    (5432,  "PostgreSQL",    "database",       "PostgreSQL"),
    (6379,  "Redis",         "database",       "Redis key-value store"),
    (27017, "MongoDB",       "database",       "MongoDB"),
    # Other notable ports observed in CICIDS
    (444,   "SNPP",          "web",            "Simple Network Paging Protocol — used for Heartbleed in CICIDS"),
    (49163, "Ephemeral",     "ephemeral",      "Dynamic/private port range — observed in CICIDS PortScan"),
    (981,   "Unassigned",    "unknown",        "Observed in CICIDS PortScan reconnaissance"),
    (7496,  "Unassigned",    "unknown",        "Observed in CICIDS PortScan reconnaissance"),
    (6689,  "Unassigned",    "unknown",        "Observed in CICIDS PortScan reconnaissance"),
    (9944,  "Unassigned",    "unknown",        "Observed in CICIDS PortScan reconnaissance"),
]


def build_port_row(port_num: int, service: str, category: str, desc: str) -> dict:
    return {
        "port_number": port_num,
        "service_name": service,
        "port_category": category,
        "is_well_known": 1 if port_num < 1024 else 0,
        "description": desc,
    }


def seed():
    """Populate dim_port with well-known ports. Idempotent."""
    with get_session() as session:
        existing = session.scalar(select(DimPort).limit(1))
        if existing:
            count = session.query(DimPort).count()
            print(f"  ⏭️  dim_port already has {count} rows — skipping (use ETL to add observed ports)")
            return

        rows = [build_port_row(*p) for p in WELL_KNOWN_PORTS]
        session.bulk_insert_mappings(DimPort, rows)
        print(f"  ✅ dim_port: inserted {len(rows)} well-known ports")
        print(f"     (Additional ports will be added during Week 3 ETL)")


if __name__ == "__main__":
    seed()