from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.utcnow()


class UserRole(str, enum.Enum):
    OWNER = "owner"
    STEWARD = "steward"
    ADMIN = "admin"
    AUDITOR = "auditor"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BackupType(str, enum.Enum):
    FULL = "full"
    INCREMENTAL = "incremental"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, native_enum=False), default=UserRole.OWNER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    sources: Mapped[list["DataSource"]] = relationship(back_populates="owner")


class DataSource(Base):
    __tablename__ = "data_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), default="postgresql")
    host: Mapped[str] = mapped_column(String(255), default="db")
    port: Mapped[int] = mapped_column(Integer, default=5432)
    database_name: Mapped[str] = mapped_column(String(120))
    username: Mapped[str] = mapped_column(String(120))
    password_encrypted: Mapped[str] = mapped_column(Text, default="")
    ssl_mode: Mapped[str] = mapped_column(String(32), default="prefer")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    checksum: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    owner: Mapped[User] = relationship(back_populates="sources")
    snapshots: Mapped[list["QuerySnapshot"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class QuerySnapshot(Base):
    __tablename__ = "query_snapshots"
    __table_args__ = (
        Index("ix_snapshots_source_collected", "source_id", "collected_at"),
        Index("ix_snapshots_fingerprint", "fingerprint"),
        Index("ix_snapshots_score", "toxicity_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"))
    query_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    query_text: Mapped[str] = mapped_column(Text)
    normalized_query: Mapped[str] = mapped_column(Text)
    database_name: Mapped[str] = mapped_column(String(120), default="")
    db_user: Mapped[str] = mapped_column(String(120), default="")
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    calls: Mapped[int] = mapped_column(BigInteger, default=0)
    rows: Mapped[int] = mapped_column(BigInteger, default=0)
    total_exec_time_ms: Mapped[float] = mapped_column(Float, default=0)
    mean_exec_time_ms: Mapped[float] = mapped_column(Float, default=0)
    max_exec_time_ms: Mapped[float] = mapped_column(Float, default=0)
    shared_blks_hit: Mapped[int] = mapped_column(BigInteger, default=0)
    shared_blks_read: Mapped[int] = mapped_column(BigInteger, default=0)
    shared_blks_written: Mapped[int] = mapped_column(BigInteger, default=0)
    temp_blks_written: Mapped[int] = mapped_column(BigInteger, default=0)
    wal_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    blk_read_time_ms: Mapped[float] = mapped_column(Float, default=0)
    blk_write_time_ms: Mapped[float] = mapped_column(Float, default=0)
    cache_hit_ratio: Mapped[float] = mapped_column(Float, default=1)
    io_bytes_estimate: Mapped[int] = mapped_column(BigInteger, default=0)
    energy_kwh: Mapped[float] = mapped_column(Float, default=0)
    cost_rub: Mapped[float] = mapped_column(Float, default=0)
    toxicity_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False), default=Severity.LOW)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    source: Mapped[DataSource] = relationship(back_populates="snapshots")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(80), index=True)
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    user: Mapped[User | None] = relationship()


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    target: Mapped[str] = mapped_column(String(64), default="query_snapshots")
    archive_after_days: Mapped[int] = mapped_column(Integer, default=90)
    delete_after_days: Mapped[int] = mapped_column(Integer, default=365)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    created_by: Mapped[User] = relationship()


class BackupRecord(Base):
    __tablename__ = "backup_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    backup_type: Mapped[BackupType] = mapped_column(Enum(BackupType, native_enum=False))
    status: Mapped[str] = mapped_column(String(32), default="created")
    file_path: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    parent_backup_id: Mapped[int | None] = mapped_column(ForeignKey("backup_records.id"), nullable=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    restored_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_by: Mapped[User] = relationship(foreign_keys=[created_by_id])
    parent: Mapped["BackupRecord | None"] = relationship(remote_side=[id])


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
