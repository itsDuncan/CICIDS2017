"""
SQLAlchemy 2.0 ORM models for the SOC Sentinel data warehouse.

All models map to the `warehouse` schema in PostgreSQL.
Schema definitions match sql/ddl/01_dimensions.sql and sql/ddl/02_facts.sql.
"""
from datetime import datetime, date
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, Date, DateTime, ForeignKey, Integer,
    Numeric, SmallInteger, String, Text, UniqueConstraint, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all warehouse models."""
    pass


# =====================================================================
# DIMENSION TABLES
# =====================================================================

class DimDate(Base):
    __tablename__ = "dim_date"
    __table_args__ = {"schema": "warehouse"}

    date_sk: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_date: Mapped[date] = mapped_column(Date, nullable=False, unique=True)
    day_of_week: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    day_name: Mapped[str] = mapped_column(String(10), nullable=False)
    day_of_month: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    day_of_year: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    week_of_year: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    month_num: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    month_name: Mapped[str] = mapped_column(String(10), nullable=False)
    quarter: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    year: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    is_weekend: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    is_business_day: Mapped[int] = mapped_column(SmallInteger, default=1, nullable=False)
    holiday_flag: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimTime(Base):
    __tablename__ = "dim_time"
    __table_args__ = {"schema": "warehouse"}

    time_sk: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    hour_24: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    minute: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    hour_12: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    am_pm: Mapped[str] = mapped_column(String(2), nullable=False)
    day_part: Mapped[str] = mapped_column(String(20), nullable=False)
    is_business_hour: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    is_after_hours: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimAsset(Base):
    __tablename__ = "dim_asset"
    __table_args__ = (
        UniqueConstraint("asset_identifier", "source_system", name="uq_dim_asset_identifier"),
        {"schema": "warehouse"},
    )

    asset_sk: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    asset_identifier: Mapped[str] = mapped_column(String(50), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50))
    mac_address: Mapped[Optional[str]] = mapped_column(String(20))
    hostname: Mapped[Optional[str]] = mapped_column(String(100))
    os_type: Mapped[Optional[str]] = mapped_column(String(50))
    business_unit: Mapped[Optional[str]] = mapped_column(String(100))
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    is_internal: Mapped[int] = mapped_column(SmallInteger, default=1, nullable=False)
    country_iso: Mapped[Optional[str]] = mapped_column(String(2))
    country_name: Mapped[Optional[str]] = mapped_column(String(100))
    city: Mapped[Optional[str]] = mapped_column(String(100))
    latitude: Mapped[Optional[float]] = mapped_column(Numeric(9, 6))
    longitude: Mapped[Optional[float]] = mapped_column(Numeric(9, 6))
    asn: Mapped[Optional[int]] = mapped_column(Integer)
    asn_org: Mapped[Optional[str]] = mapped_column(String(200))
    abuse_confidence: Mapped[Optional[int]] = mapped_column(SmallInteger)
    is_known_attacker: Mapped[int] = mapped_column(SmallInteger, default=0)
    source_system: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimUser(Base):
    __tablename__ = "dim_user"
    __table_args__ = {"schema": "warehouse"}

    user_sk: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(20), nullable=False)
    employee_name: Mapped[Optional[str]] = mapped_column(String(200))
    email_address: Mapped[Optional[str]] = mapped_column(String(200))
    role: Mapped[Optional[str]] = mapped_column(String(100))
    business_unit: Mapped[Optional[str]] = mapped_column(String(50))
    functional_unit: Mapped[Optional[str]] = mapped_column(String(100))
    department: Mapped[Optional[str]] = mapped_column(String(100))
    team: Mapped[Optional[str]] = mapped_column(String(50))
    supervisor_name: Mapped[Optional[str]] = mapped_column(String(200))
    ocean_o: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ocean_c: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ocean_e: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ocean_a: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ocean_n: Mapped[Optional[int]] = mapped_column(SmallInteger)
    is_malicious: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    malicious_scenario: Mapped[Optional[int]] = mapped_column(SmallInteger)
    attack_window_start: Mapped[Optional[datetime]] = mapped_column(DateTime)
    attack_window_end: Mapped[Optional[datetime]] = mapped_column(DateTime)
    valid_from: Mapped[date] = mapped_column(Date, nullable=False)
    valid_to: Mapped[Optional[date]] = mapped_column(Date)
    is_current: Mapped[int] = mapped_column(SmallInteger, default=1, nullable=False)
    source_system: Mapped[str] = mapped_column(String(20), default="CERT", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimActivityType(Base):
    __tablename__ = "dim_activity_type"
    __table_args__ = {"schema": "warehouse"}

    activity_sk: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    activity_name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    activity_category: Mapped[str] = mapped_column(String(30), nullable=False)
    risk_weight: Mapped[float] = mapped_column(Numeric(3, 1), default=1.0)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimAttackType(Base):
    __tablename__ = "dim_attack_type"
    __table_args__ = {"schema": "warehouse"}

    attack_sk: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    attack_label: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    attack_family: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(50))
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimProtocol(Base):
    __tablename__ = "dim_protocol"
    __table_args__ = {"schema": "warehouse"}

    protocol_sk: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    protocol_num: Mapped[int] = mapped_column(SmallInteger, nullable=False, unique=True)
    protocol_name: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class DimPort(Base):
    __tablename__ = "dim_port"
    __table_args__ = {"schema": "warehouse"}

    port_sk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    service_name: Mapped[Optional[str]] = mapped_column(String(50))
    port_category: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    is_well_known: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


# =====================================================================
# FACT TABLES
# =====================================================================

class FactSecurityEvent(Base):
    """CICIDS network flow events — Phase 1."""
    __tablename__ = "fact_security_event"
    __table_args__ = {"schema": "warehouse"}

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_system: Mapped[str] = mapped_column(String(20), default="CICIDS", nullable=False)

    # Foreign keys
    date_sk: Mapped[int] = mapped_column(Integer, ForeignKey("warehouse.dim_date.date_sk"), nullable=False)
    time_sk: Mapped[int] = mapped_column(SmallInteger, ForeignKey("warehouse.dim_time.time_sk"), nullable=False)
    src_asset_sk: Mapped[Optional[int]] = mapped_column(BigInteger, ForeignKey("warehouse.dim_asset.asset_sk"))
    dest_asset_sk: Mapped[Optional[int]] = mapped_column(BigInteger, ForeignKey("warehouse.dim_asset.asset_sk"))
    src_port_sk: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("warehouse.dim_port.port_sk"))
    dest_port_sk: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("warehouse.dim_port.port_sk"))
    protocol_sk: Mapped[Optional[int]] = mapped_column(SmallInteger, ForeignKey("warehouse.dim_protocol.protocol_sk"))
    attack_sk: Mapped[Optional[int]] = mapped_column(SmallInteger, ForeignKey("warehouse.dim_attack_type.attack_sk"))

    # Natural fields
    event_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    flow_id: Mapped[Optional[str]] = mapped_column(String(100))

    # Volumetric measures
    flow_duration: Mapped[Optional[int]] = mapped_column(BigInteger)
    total_fwd_packets: Mapped[Optional[int]] = mapped_column(Integer)
    total_bwd_packets: Mapped[Optional[int]] = mapped_column(Integer)
    total_length_fwd: Mapped[Optional[int]] = mapped_column(Integer)
    total_length_bwd: Mapped[Optional[int]] = mapped_column(Integer)
    flow_bytes_per_sec: Mapped[Optional[float]] = mapped_column()
    flow_packets_per_sec: Mapped[Optional[float]] = mapped_column()

    # Packet length stats
    fwd_pkt_len_max: Mapped[Optional[int]] = mapped_column(Integer)
    fwd_pkt_len_min: Mapped[Optional[int]] = mapped_column(Integer)
    fwd_pkt_len_mean: Mapped[Optional[float]] = mapped_column()
    fwd_pkt_len_std: Mapped[Optional[float]] = mapped_column()
    bwd_pkt_len_max: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_pkt_len_min: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_pkt_len_mean: Mapped[Optional[float]] = mapped_column()
    bwd_pkt_len_std: Mapped[Optional[float]] = mapped_column()
    pkt_len_min: Mapped[Optional[int]] = mapped_column(Integer)
    pkt_len_max: Mapped[Optional[int]] = mapped_column(Integer)
    pkt_len_mean: Mapped[Optional[float]] = mapped_column()
    pkt_len_std: Mapped[Optional[float]] = mapped_column()
    pkt_len_variance: Mapped[Optional[float]] = mapped_column()

    # Inter-arrival times
    flow_iat_mean: Mapped[Optional[float]] = mapped_column()
    flow_iat_std: Mapped[Optional[float]] = mapped_column()
    flow_iat_max: Mapped[Optional[int]] = mapped_column(BigInteger)
    flow_iat_min: Mapped[Optional[int]] = mapped_column(BigInteger)
    fwd_iat_total: Mapped[Optional[int]] = mapped_column(BigInteger)
    fwd_iat_mean: Mapped[Optional[float]] = mapped_column()
    fwd_iat_std: Mapped[Optional[float]] = mapped_column()
    fwd_iat_max: Mapped[Optional[int]] = mapped_column(BigInteger)
    fwd_iat_min: Mapped[Optional[int]] = mapped_column(BigInteger)
    bwd_iat_total: Mapped[Optional[int]] = mapped_column(BigInteger)
    bwd_iat_mean: Mapped[Optional[float]] = mapped_column()
    bwd_iat_std: Mapped[Optional[float]] = mapped_column()
    bwd_iat_max: Mapped[Optional[int]] = mapped_column(BigInteger)
    bwd_iat_min: Mapped[Optional[int]] = mapped_column(BigInteger)

    # Flag counts
    fwd_psh_flags: Mapped[Optional[int]] = mapped_column(SmallInteger)
    bwd_psh_flags: Mapped[Optional[int]] = mapped_column(SmallInteger)
    fwd_urg_flags: Mapped[Optional[int]] = mapped_column(SmallInteger)
    bwd_urg_flags: Mapped[Optional[int]] = mapped_column(SmallInteger)
    fin_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    syn_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    rst_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    psh_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ack_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    urg_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    cwe_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    ece_flag_count: Mapped[Optional[int]] = mapped_column(SmallInteger)

    # Header lengths and rates
    fwd_header_length: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_header_length: Mapped[Optional[int]] = mapped_column(Integer)
    fwd_pkts_per_sec: Mapped[Optional[float]] = mapped_column()
    bwd_pkts_per_sec: Mapped[Optional[float]] = mapped_column()

    # Other measures
    down_up_ratio: Mapped[Optional[int]] = mapped_column(SmallInteger)
    avg_pkt_size: Mapped[Optional[float]] = mapped_column()
    avg_fwd_seg_size: Mapped[Optional[float]] = mapped_column()
    avg_bwd_seg_size: Mapped[Optional[float]] = mapped_column()

    # Bulk measures
    fwd_avg_bytes_bulk: Mapped[Optional[int]] = mapped_column(Integer)
    fwd_avg_pkts_bulk: Mapped[Optional[int]] = mapped_column(Integer)
    fwd_avg_bulk_rate: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_avg_bytes_bulk: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_avg_pkts_bulk: Mapped[Optional[int]] = mapped_column(Integer)
    bwd_avg_bulk_rate: Mapped[Optional[int]] = mapped_column(Integer)

    # Subflow measures
    subflow_fwd_pkts: Mapped[Optional[int]] = mapped_column(Integer)
    subflow_fwd_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    subflow_bwd_pkts: Mapped[Optional[int]] = mapped_column(Integer)
    subflow_bwd_bytes: Mapped[Optional[int]] = mapped_column(Integer)

    # Window sizes
    init_win_bytes_fwd: Mapped[Optional[int]] = mapped_column(Integer)
    init_win_bytes_bwd: Mapped[Optional[int]] = mapped_column(Integer)
    act_data_pkt_fwd: Mapped[Optional[int]] = mapped_column(Integer)
    min_seg_size_fwd: Mapped[Optional[int]] = mapped_column(Integer)

    # Active/idle measures
    active_mean: Mapped[Optional[float]] = mapped_column()
    active_std: Mapped[Optional[float]] = mapped_column()
    active_max: Mapped[Optional[int]] = mapped_column(BigInteger)
    active_min: Mapped[Optional[int]] = mapped_column(BigInteger)
    idle_mean: Mapped[Optional[float]] = mapped_column()
    idle_std: Mapped[Optional[float]] = mapped_column()
    idle_max: Mapped[Optional[int]] = mapped_column(BigInteger)
    idle_min: Mapped[Optional[int]] = mapped_column(BigInteger)

    # Labels
    is_attack: Mapped[Optional[int]] = mapped_column(SmallInteger)
    attack_family_denorm: Mapped[Optional[str]] = mapped_column(String(50))

    # ML output
    priority_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4))
    priority_label: Mapped[Optional[str]] = mapped_column(String(20))
    anomaly_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4))
    model_version: Mapped[Optional[str]] = mapped_column(String(20))
    scored_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    loaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class FactUserActivity(Base):
    """CERT employee activity events — Phase 2."""
    __tablename__ = "fact_user_activity"
    __table_args__ = {"schema": "warehouse"}

    activity_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_system: Mapped[str] = mapped_column(String(20), default="CERT", nullable=False)

    # Foreign keys
    date_sk: Mapped[int] = mapped_column(Integer, ForeignKey("warehouse.dim_date.date_sk"), nullable=False)
    time_sk: Mapped[int] = mapped_column(SmallInteger, ForeignKey("warehouse.dim_time.time_sk"), nullable=False)
    user_sk: Mapped[int] = mapped_column(BigInteger, ForeignKey("warehouse.dim_user.user_sk"), nullable=False)
    asset_sk: Mapped[Optional[int]] = mapped_column(BigInteger, ForeignKey("warehouse.dim_asset.asset_sk"))
    activity_sk: Mapped[int] = mapped_column(SmallInteger, ForeignKey("warehouse.dim_activity_type.activity_sk"), nullable=False)

    # Natural identifiers
    natural_event_id: Mapped[Optional[str]] = mapped_column(String(50))
    event_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Activity-specific fields
    filename: Mapped[Optional[str]] = mapped_column(String(200))
    file_extension: Mapped[Optional[str]] = mapped_column(String(20))
    to_recipients_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    external_recipient_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    attachment_count: Mapped[Optional[int]] = mapped_column(SmallInteger)
    size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    url_domain: Mapped[Optional[str]] = mapped_column(String(200))

    # Derived temporal
    is_after_hours: Mapped[Optional[int]] = mapped_column(SmallInteger)
    is_weekend: Mapped[Optional[int]] = mapped_column(SmallInteger)

    # Labels (denormalized for query speed)
    is_malicious_user: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    in_attack_window: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)

    # ML output
    risk_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4))
    anomaly_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4))
    model_version: Mapped[Optional[str]] = mapped_column(String(20))
    scored_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    loaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


# =====================================================================
# Convenience: list of all models for batch operations
# =====================================================================
ALL_DIMS = [
    DimDate, DimTime, DimAsset, DimUser,
    DimActivityType, DimAttackType, DimProtocol, DimPort
]

ALL_FACTS = [FactSecurityEvent, FactUserActivity]

ALL_MODELS = ALL_DIMS + ALL_FACTS