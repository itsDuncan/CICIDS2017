"""
Seed dim_attack_type with all 16 attack labels observed in CICIDS2017.
Each label maps to an attack family, severity, and (where applicable) MITRE ATT&CK metadata.
"""
from sqlalchemy import select

from src.warehouse import get_session
from src.warehouse.models import DimAttackType


ATTACK_TYPES = [
    # Benign baseline
    {
        "attack_label": "BENIGN",
        "attack_family": "Benign",
        "severity": "info",
        "mitre_technique_id": None,
        "mitre_tactic": None,
        "description": "Normal network traffic — no malicious activity detected.",
    },
    # Unlabeled (data quality artifact in CICIDS2017 WebAttacks file)
    {
        "attack_label": "Unlabeled",
        "attack_family": "Unlabeled",
        "severity": "info",
        "mitre_technique_id": None,
        "mitre_tactic": None,
        "description": "Flow records missing labels in source — known CICIDS2017 data quality issue.",
    },
    # DoS variants
    {
        "attack_label": "DoS Hulk",
        "attack_family": "DoS",
        "severity": "high",
        "mitre_technique_id": "T1499.002",
        "mitre_tactic": "Impact",
        "description": "Hulk DoS — generates a massive volume of unique HTTP requests to overwhelm a server.",
    },
    {
        "attack_label": "DoS GoldenEye",
        "attack_family": "DoS",
        "severity": "high",
        "mitre_technique_id": "T1499.002",
        "mitre_tactic": "Impact",
        "description": "GoldenEye DoS — HTTP-layer attack using Keep-Alive and No-Cache headers to exhaust resources.",
    },
    {
        "attack_label": "DoS slowloris",
        "attack_family": "DoS",
        "severity": "high",
        "mitre_technique_id": "T1499.001",
        "mitre_tactic": "Impact",
        "description": "Slowloris — opens many connections and keeps them alive with partial requests.",
    },
    {
        "attack_label": "DoS Slowhttptest",
        "attack_family": "DoS",
        "severity": "high",
        "mitre_technique_id": "T1499.001",
        "mitre_tactic": "Impact",
        "description": "Slow HTTP test — exhausts server resources with slow request bodies.",
    },
    # DDoS
    {
        "attack_label": "DDoS",
        "attack_family": "DDoS",
        "severity": "critical",
        "mitre_technique_id": "T1498",
        "mitre_tactic": "Impact",
        "description": "Distributed Denial of Service — multiple attackers flood target with traffic.",
    },
    # Brute force
    {
        "attack_label": "FTP-Patator",
        "attack_family": "Brute Force",
        "severity": "medium",
        "mitre_technique_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "description": "FTP credential brute force using Patator tool.",
    },
    {
        "attack_label": "SSH-Patator",
        "attack_family": "Brute Force",
        "severity": "medium",
        "mitre_technique_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "description": "SSH credential brute force using Patator tool.",
    },
    # Reconnaissance
    {
        "attack_label": "PortScan",
        "attack_family": "Reconnaissance",
        "severity": "low",
        "mitre_technique_id": "T1046",
        "mitre_tactic": "Discovery",
        "description": "Network port scanning to enumerate accessible services.",
    },
    # Web attacks
    {
        "attack_label": "Web Attack - Brute Force",
        "attack_family": "Web Attack",
        "severity": "medium",
        "mitre_technique_id": "T1110",
        "mitre_tactic": "Credential Access",
        "description": "Brute-force authentication attempt against a web application.",
    },
    {
        "attack_label": "Web Attack - XSS",
        "attack_family": "Web Attack",
        "severity": "medium",
        "mitre_technique_id": "T1059.007",
        "mitre_tactic": "Execution",
        "description": "Cross-Site Scripting — injects malicious scripts into trusted web pages.",
    },
    {
        "attack_label": "Web Attack - Sql Injection",
        "attack_family": "Web Attack",
        "severity": "high",
        "mitre_technique_id": "T1190",
        "mitre_tactic": "Initial Access",
        "description": "SQL injection — manipulates database queries via crafted input.",
    },
    # Botnet
    {
        "attack_label": "Bot",
        "attack_family": "Botnet",
        "severity": "high",
        "mitre_technique_id": "T1071",
        "mitre_tactic": "Command and Control",
        "description": "Botnet C2 traffic — compromised host communicating with command server.",
    },
    # Infiltration
    {
        "attack_label": "Infiltration",
        "attack_family": "Infiltration",
        "severity": "critical",
        "mitre_technique_id": "T1133",
        "mitre_tactic": "Initial Access",
        "description": "Infiltration via removable media or vulnerable service.",
    },
    # Heartbleed
    {
        "attack_label": "Heartbleed",
        "attack_family": "Exploit",
        "severity": "critical",
        "mitre_technique_id": "T1190",
        "mitre_tactic": "Initial Access",
        "description": "OpenSSL Heartbleed CVE-2014-0160 — exposes server memory via TLS heartbeat.",
    },
]


def seed():
    """Populate dim_attack_type. Idempotent."""
    with get_session() as session:
        existing = session.scalar(select(DimAttackType).limit(1))
        if existing:
            count = session.query(DimAttackType).count()
            print(f"  ⏭️  dim_attack_type already has {count} rows — skipping")
            return

        session.bulk_insert_mappings(DimAttackType, ATTACK_TYPES)
        print(f"  ✅ dim_attack_type: inserted {len(ATTACK_TYPES)} rows")


if __name__ == "__main__":
    seed()