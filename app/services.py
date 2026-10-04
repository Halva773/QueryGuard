from __future__ import annotations

import hashlib
import json
import random
from enum import Enum as PythonEnum
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import URL, create_engine, delete, desc, select
from sqlalchemy.orm import Session

from .analytics import (
    BLOCK_SIZE,
    calculate_toxicity,
    ensure_default_settings,
    estimate_impact,
    normalize_query,
    query_fingerprint,
)
from .cache import cache
from .config import settings
from .models import (
    AuditLog,
    BackupRecord,
    BackupType,
    DataSource,
    QuerySnapshot,
    RetentionPolicy,
    Severity,
    SystemSetting,
    User,
    UserRole,
)
from .security import decrypt_secret, hash_password


def write_audit(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: Any = "",
    user_id: Optional[int] = None,
    details: Optional[dict[str, Any]] = None,
    ip_address: str = "",
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id or ""),
            details=details or {},
            ip_address=ip_address,
        )
    )


def _source_engine(source: DataSource):
    url = URL.create(
        "postgresql+psycopg",
        username=source.username,
        password=decrypt_secret(source.password_encrypted),
        host=source.host,
        port=source.port,
        database=source.database_name,
        query={"sslmode": source.ssl_mode} if source.ssl_mode else {},
    )
    return create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 5})


PG_STAT_SQL = """
/* queryguard */
SELECT
    s.queryid::text AS query_id,
    s.query,
    d.datname AS database_name,
    r.rolname AS db_user,
    s.calls,
    s.rows,
    s.total_exec_time AS total_exec_time_ms,
    s.mean_exec_time AS mean_exec_time_ms,
    s.max_exec_time AS max_exec_time_ms,
    s.shared_blks_hit,
    s.shared_blks_read,
    s.shared_blks_written,
    s.temp_blks_written,
    COALESCE(s.wal_bytes, 0)::bigint AS wal_bytes,
    s.blk_read_time AS blk_read_time_ms,
    s.blk_write_time AS blk_write_time_ms
FROM pg_stat_statements s
JOIN pg_database d ON d.oid = s.dbid
JOIN pg_roles r ON r.oid = s.userid
WHERE s.query NOT LIKE '/* queryguard */%'
  AND s.calls > 0
ORDER BY s.total_exec_time DESC
LIMIT 500
"""


def test_source_connection(source: DataSource) -> tuple[bool, str]:
    if source.kind == "demo":
        return True, "Демонстрационный источник доступен"
    engine = _source_engine(source)
    try:
        with engine.connect() as conn:
            version = conn.exec_driver_sql("SELECT version()").scalar_one()
            extension = conn.exec_driver_sql(
                "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements')"
            ).scalar_one()
        if not extension:
            return False, "Подключение установлено, но расширение pg_stat_statements не включено"
        return True, str(version).split(",")[0]
    except Exception as exc:  # normalized to a user-safe message by the caller
        return False, f"Подключение не установлено: {exc.__class__.__name__}"
    finally:
        engine.dispose()


def collect_source(db: Session, source: DataSource, user_id: int, ip_address: str = "") -> int:
    if source.kind == "demo":
        count = seed_query_snapshots(db, source, rounds=1)
        write_audit(db, "collect", "data_source", source.id, user_id, {"rows": count}, ip_address)
        db.commit()
        cache.delete_pattern("dashboard:*")
        return count

    with cache.lock(f"collector:{source.id}", timeout=120) as acquired:
        if not acquired:
            raise RuntimeError("Сбор статистики для источника уже выполняется")
        engine = _source_engine(source)
        try:
            with engine.connect() as conn:
                rows = [dict(row._mapping) for row in conn.exec_driver_sql(PG_STAT_SQL)]
        except Exception as exc:
            raise RuntimeError(
                "Не удалось прочитать pg_stat_statements. Проверьте доступ, расширение и track_io_timing."
            ) from exc
        finally:
            engine.dispose()

        collected_at = datetime.utcnow()
        for row in rows:
            score, severity, parts = calculate_toxicity(row)
            energy, cost = estimate_impact(db, row["total_exec_time_ms"], int(parts["io_bytes"]))
            query = row["query"] or ""
            db.add(
                QuerySnapshot(
                    source_id=source.id,
                    query_id=row["query_id"],
                    fingerprint=query_fingerprint(query),
                    query_text=query,
                    normalized_query=normalize_query(query),
                    database_name=row["database_name"],
                    db_user=row["db_user"],
                    collected_at=collected_at,
                    calls=int(row["calls"] or 0),
                    rows=int(row["rows"] or 0),
                    total_exec_time_ms=float(row["total_exec_time_ms"] or 0),
                    mean_exec_time_ms=float(row["mean_exec_time_ms"] or 0),
                    max_exec_time_ms=float(row["max_exec_time_ms"] or 0),
                    shared_blks_hit=int(row["shared_blks_hit"] or 0),
                    shared_blks_read=int(row["shared_blks_read"] or 0),
                    shared_blks_written=int(row["shared_blks_written"] or 0),
                    temp_blks_written=int(row["temp_blks_written"] or 0),
                    wal_bytes=int(row["wal_bytes"] or 0),
                    blk_read_time_ms=float(row["blk_read_time_ms"] or 0),
                    blk_write_time_ms=float(row["blk_write_time_ms"] or 0),
                    cache_hit_ratio=float(parts["cache_hit_ratio"]),
                    io_bytes_estimate=int(parts["io_bytes"]),
                    energy_kwh=energy,
                    cost_rub=cost,
                    toxicity_score=score,
                    severity=severity,
                )
            )
        source.last_accessed_at = collected_at
        source.last_collected_at = collected_at
        source.checksum = hashlib.sha256(
            f"{source.name}:{source.host}:{source.database_name}:{len(rows)}:{collected_at.isoformat()}".encode()
        ).hexdigest()
        write_audit(db, "collect", "data_source", source.id, user_id, {"rows": len(rows)}, ip_address)
        db.commit()
        cache.delete_pattern("dashboard:*")
        return len(rows)


DEMO_QUERIES = [
    (
        "SELECT p.category_id, SUM(oi.quantity * oi.unit_price) FROM order_items oi "
        "JOIN products p ON p.id = oi.product_id JOIN orders o ON o.id = oi.order_id "
        "WHERE o.created_at >= now() - interval '90 days' GROUP BY p.category_id ORDER BY 2 DESC",
        6100,
        245_000,
        890_000,
        42_000,
    ),
    (
        "SELECT s.store_id, date_trunc('day', s.sold_at), SUM(s.total) FROM sales s "
        "WHERE s.sold_at BETWEEN $1 AND $2 GROUP BY 1, 2",
        820,
        48_000,
        65_000,
        0,
    ),
    (
        "UPDATE inventory i SET quantity = quantity - x.qty FROM order_items x "
        "WHERE i.product_id = x.product_id AND x.order_id = $1",
        180,
        31_000,
        9_000,
        0,
    ),
    (
        "SELECT c.segment, COUNT(DISTINCT o.customer_id), AVG(o.total) FROM customers c "
        "JOIN orders o ON o.customer_id = c.id GROUP BY c.segment",
        3900,
        112_000,
        340_000,
        18_000,
    ),
    (
        "SELECT * FROM stock_movements WHERE product_id = $1 ORDER BY created_at DESC LIMIT 100",
        22,
        1_800,
        320,
        0,
    ),
    (
        "SELECT supplier_id, jsonb_agg(to_jsonb(p)) FROM products p GROUP BY supplier_id",
        9700,
        361_000,
        1_250_000,
        91_000,
    ),
    (
        "DELETE FROM cart_items WHERE cart_id IN (SELECT id FROM carts WHERE updated_at < $1)",
        460,
        17_000,
        12_000,
        0,
    ),
    (
        "SELECT o.id, o.total, c.email FROM orders o JOIN customers c ON c.id=o.customer_id "
        "WHERE lower(c.email)=lower($1)",
        1250,
        84_000,
        110_000,
        4_000,
    ),
]


def seed_query_snapshots(db: Session, source: DataSource, rounds: int = 7) -> int:
    rng = random.Random(42 + (db.query(QuerySnapshot).count() if source.id else 0))
    count = 0
    base = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    for day in range(rounds):
        collected_at = base - timedelta(days=rounds - day - 1)
        for idx, (query, mean, blocks_read, hits, temp) in enumerate(DEMO_QUERIES):
            factor = 0.86 + rng.random() * 0.34
            calls = rng.randint(25, 1800)
            row = {
                "mean_exec_time_ms": mean * factor,
                "total_exec_time_ms": mean * calls * factor,
                "shared_blks_hit": int(hits * factor),
                "shared_blks_read": int(blocks_read * factor),
                "shared_blks_written": int(blocks_read * 0.025 * factor),
                "temp_blks_written": int(temp * factor),
                "wal_bytes": int(blocks_read * BLOCK_SIZE * 0.08 * factor),
            }
            score, severity, parts = calculate_toxicity(row)
            energy, cost = estimate_impact(db, row["total_exec_time_ms"], int(parts["io_bytes"]))
            db.add(
                QuerySnapshot(
                    source_id=source.id,
                    query_id=str(10_000 + idx),
                    fingerprint=query_fingerprint(query),
                    query_text=query,
                    normalized_query=normalize_query(query),
                    database_name="retail_analytics",
                    db_user="analytics_service" if idx % 2 == 0 else "retail_app",
                    collected_at=collected_at,
                    calls=calls,
                    rows=rng.randint(100, 2_000_000),
                    total_exec_time_ms=row["total_exec_time_ms"],
                    mean_exec_time_ms=row["mean_exec_time_ms"],
                    max_exec_time_ms=row["mean_exec_time_ms"] * rng.uniform(1.2, 4.5),
                    shared_blks_hit=row["shared_blks_hit"],
                    shared_blks_read=row["shared_blks_read"],
                    shared_blks_written=row["shared_blks_written"],
                    temp_blks_written=row["temp_blks_written"],
                    wal_bytes=row["wal_bytes"],
                    blk_read_time_ms=row["shared_blks_read"] * 0.02,
                    blk_write_time_ms=row["shared_blks_written"] * 0.03,
                    cache_hit_ratio=float(parts["cache_hit_ratio"]),
                    io_bytes_estimate=int(parts["io_bytes"]),
                    energy_kwh=energy,
                    cost_rub=cost,
                    toxicity_score=score,
                    severity=severity,
                )
            )
            count += 1
    source.last_collected_at = base
    source.last_accessed_at = base
    source.checksum = hashlib.sha256(f"demo:{count}:{base.isoformat()}".encode()).hexdigest()
    db.commit()
    return count


def seed_demo(db: Session) -> None:
    ensure_default_settings(db)
    if not settings.seed_demo:
        return
    admin = db.scalar(select(User).where(User.username == "admin"))
    if not admin:
        accounts = [
            ("admin", "admin@queryguard.local", settings.demo_admin_password, UserRole.ADMIN),
            ("steward", "steward@queryguard.local", "Steward123!", UserRole.STEWARD),
            ("auditor", "auditor@queryguard.local", "Auditor123!", UserRole.AUDITOR),
            ("owner", "owner@queryguard.local", "Owner123!", UserRole.OWNER),
        ]
        for username, email, password, role in accounts:
            db.add(User(username=username, email=email, password_hash=hash_password(password), role=role))
        db.commit()
        admin = db.scalar(select(User).where(User.username == "admin"))
    owner = db.scalar(select(User).where(User.username == "owner")) or admin
    source = db.scalar(select(DataSource).where(DataSource.name == "Розничная аналитика — демо"))
    if not source:
        source = DataSource(
            name="Розничная аналитика — демо",
            kind="demo",
            host="demo",
            port=5432,
            database_name="retail_analytics",
            username="analytics_service",
            owner_id=owner.id,
            checksum=hashlib.sha256(b"retail-demo-source").hexdigest(),
        )
        db.add(source)
        db.commit()
        seed_query_snapshots(db, source, rounds=7)
    if not db.scalar(select(RetentionPolicy).where(RetentionPolicy.name == "Снимки запросов")):
        db.add(
            RetentionPolicy(
                name="Снимки запросов",
                target="query_snapshots",
                archive_after_days=90,
                delete_after_days=365,
                enabled=True,
                created_by_id=admin.id,
            )
        )
        db.commit()


def run_retention(db: Session, user_id: int, confirm_delete: bool = False) -> dict[str, int]:
    now = datetime.utcnow()
    archived = 0
    deleted = 0
    policies = db.scalars(select(RetentionPolicy).where(RetentionPolicy.enabled.is_(True))).all()
    for policy in policies:
        if policy.target != "query_snapshots":
            continue
        archive_cutoff = now - timedelta(days=policy.archive_after_days)
        for row in db.scalars(
            select(QuerySnapshot).where(
                QuerySnapshot.collected_at < archive_cutoff, QuerySnapshot.is_archived.is_(False)
            )
        ).all():
            row.is_archived = True
            row.archived_at = now
            archived += 1
        if confirm_delete:
            delete_cutoff = now - timedelta(days=policy.delete_after_days)
            candidates = db.scalars(
                select(QuerySnapshot).where(
                    QuerySnapshot.collected_at < delete_cutoff, QuerySnapshot.is_archived.is_(True)
                )
            ).all()
            deleted += len(candidates)
            for row in candidates:
                db.delete(row)
    write_audit(
        db,
        "retention_run",
        "query_snapshots",
        user_id=user_id,
        details={"archived": archived, "deleted": deleted, "confirmed": confirm_delete},
    )
    db.commit()
    cache.delete_pattern("dashboard:*")
    return {"archived": archived, "deleted": deleted}


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return value


def _model_rows(db: Session, model, since: Optional[datetime] = None) -> list[dict[str, Any]]:
    stmt = select(model)
    if since is not None:
        if hasattr(model, "updated_at"):
            stmt = stmt.where(model.updated_at > since)
        elif hasattr(model, "created_at"):
            stmt = stmt.where(model.created_at > since)
    rows = []
    for item in db.scalars(stmt).all():
        rows.append({column.name: _iso(getattr(item, column.name)) for column in item.__table__.columns})
    return rows


def create_backup(db: Session, backup_type: BackupType, user_id: int) -> BackupRecord:
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    parent = db.scalar(
        select(BackupRecord)
        .where(BackupRecord.status.in_(["verified", "restored"]))
        .order_by(desc(BackupRecord.created_at))
    )
    if backup_type == BackupType.INCREMENTAL and parent is None:
        raise ValueError("Сначала создайте и проверьте полную резервную копию")
    since = parent.created_at if backup_type == BackupType.INCREMENTAL and parent else None
    payload = {
        "format": "queryguard-backup-v1",
        "backup_type": backup_type.value,
        "created_at": datetime.utcnow().isoformat(),
        "since": since.isoformat() if since else None,
        "tables": {
            "users": _model_rows(db, User, since),
            "data_sources": _model_rows(db, DataSource, since),
            "query_snapshots": _model_rows(db, QuerySnapshot, since),
            "audit_logs": _model_rows(db, AuditLog, since),
            "retention_policies": _model_rows(db, RetentionPolicy, since),
            "system_settings": _model_rows(db, SystemSetting, None),
        },
    }
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
    path = settings.backup_dir / f"queryguard-{backup_type.value}-{stamp}.json"
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    path.write_bytes(raw)
    checksum = hashlib.sha256(raw).hexdigest()
    record = BackupRecord(
        backup_type=backup_type,
        status="created",
        file_path=str(path),
        checksum=checksum,
        size_bytes=len(raw),
        parent_backup_id=parent.id if since and parent else None,
        created_by_id=user_id,
    )
    db.add(record)
    db.flush()
    write_audit(db, "backup_create", "backup", record.id, user_id, {"type": backup_type.value})
    db.commit()
    return record


def _read_backup_payload(record: BackupRecord) -> dict[str, Any] | None:
    path = Path(record.file_path)
    valid = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == record.checksum
    if valid:
        try:
            payload = json.loads(path.read_text("utf-8"))
            valid = (
                payload.get("format") == "queryguard-backup-v1"
                and isinstance(payload.get("tables"), dict)
                and all(isinstance(rows, list) for rows in payload["tables"].values())
            )
        except (ValueError, OSError):
            valid = False
    return payload if valid else None


def verify_backup(db: Session, record: BackupRecord, user_id: int) -> bool:
    valid = _read_backup_payload(record) is not None
    record.status = "verified" if valid else "corrupt"
    record.verified_at = datetime.utcnow() if valid else None
    write_audit(db, "backup_verify", "backup", record.id, user_id, {"valid": valid})
    db.commit()
    return valid


def _restore_columns(item: Any, row: dict[str, Any], excluded: set[str] | None = None) -> None:
    excluded = excluded or set()
    for column in item.__table__.columns:
        if column.name in excluded or column.name not in row:
            continue
        value = row[column.name]
        enum_class = getattr(column.type, "enum_class", None)
        if value is not None and enum_class and issubclass(enum_class, PythonEnum):
            value = enum_class(value)
        elif value is not None and getattr(column.type, "python_type", None) is datetime:
            value = datetime.fromisoformat(value) if isinstance(value, str) else value
        setattr(item, column.name, value)


def _apply_backup_payload(db: Session, payload: dict[str, Any]) -> dict[str, int]:
    restored = {
        "users": 0,
        "settings": 0,
        "policies": 0,
        "sources": 0,
        "queries": 0,
        "audit_logs": 0,
    }
    user_map: dict[int, int] = {}
    source_map: dict[int, int] = {}

    for row in payload["tables"].get("users", []):
        old_id = int(row["id"])
        item = db.scalar(select(User).where(User.username == row["username"]))
        if item is None:
            item = User(id=old_id) if db.get(User, old_id) is None else User()
            db.add(item)
        _restore_columns(item, row, {"id"})
        db.flush()
        user_map[old_id] = item.id
        restored["users"] += 1

    for row in payload["tables"].get("system_settings", []):
        item = db.get(SystemSetting, row["key"])
        if item:
            _restore_columns(item, row, {"key"})
        else:
            item = SystemSetting(key=row["key"], value=row["value"])
            _restore_columns(item, row, {"key"})
            db.add(item)
        restored["settings"] += 1

    for row in payload["tables"].get("data_sources", []):
        old_id = int(row["id"])
        item = db.scalar(select(DataSource).where(DataSource.name == row["name"]))
        if item is None:
            item = DataSource(id=old_id) if db.get(DataSource, old_id) is None else DataSource()
            db.add(item)
        _restore_columns(item, row, {"id", "owner_id"})
        item.owner_id = user_map.get(int(row["owner_id"]), int(row["owner_id"]))
        db.flush()
        source_map[old_id] = item.id
        restored["sources"] += 1

    for row in payload["tables"].get("retention_policies", []):
        item = db.scalar(select(RetentionPolicy).where(RetentionPolicy.name == row["name"]))
        old_id = int(row["id"])
        if item is None:
            item = RetentionPolicy(id=old_id) if db.get(RetentionPolicy, old_id) is None else RetentionPolicy()
            db.add(item)
        _restore_columns(item, row, {"id", "created_by_id"})
        item.created_by_id = user_map.get(
            int(row["created_by_id"]), int(row["created_by_id"])
        )
        restored["policies"] += 1

    for row in payload["tables"].get("query_snapshots", []):
        old_id = int(row["id"])
        source_id = source_map.get(int(row["source_id"]), int(row["source_id"]))
        collected_at = datetime.fromisoformat(row["collected_at"])
        item = db.scalar(
            select(QuerySnapshot).where(
                QuerySnapshot.source_id == source_id,
                QuerySnapshot.query_id == str(row["query_id"]),
                QuerySnapshot.collected_at == collected_at,
            )
        )
        if item is None:
            item = QuerySnapshot(id=old_id) if db.get(QuerySnapshot, old_id) is None else QuerySnapshot()
            db.add(item)
        _restore_columns(item, row, {"id", "source_id"})
        item.source_id = source_id
        restored["queries"] += 1

    db.flush()
    for row in payload["tables"].get("audit_logs", []):
        old_id = int(row["id"])
        if db.get(AuditLog, old_id) is not None:
            continue
        item = AuditLog(id=old_id)
        _restore_columns(item, row, {"id", "user_id"})
        old_user_id = row.get("user_id")
        item.user_id = user_map.get(int(old_user_id), int(old_user_id)) if old_user_id else None
        db.add(item)
        restored["audit_logs"] += 1
    return restored


def restore_backup(db: Session, record: BackupRecord, user_id: int) -> dict[str, int]:
    chain: list[tuple[BackupRecord, dict[str, Any]]] = []
    current: BackupRecord | None = record
    visited: set[int] = set()
    while current is not None:
        if current.id in visited:
            raise ValueError("Обнаружен цикл в цепочке резервных копий")
        visited.add(current.id)
        payload = _read_backup_payload(current)
        if payload is None:
            raise ValueError(f"Контрольная сумма копии #{current.id} не совпадает")
        chain.append((current, payload))
        if current.backup_type == BackupType.FULL:
            break
        if current.parent_backup_id is None:
            raise ValueError("Для инкрементальной копии не найдена базовая полная копия")
        current = db.get(BackupRecord, current.parent_backup_id)
    if not chain or chain[-1][0].backup_type != BackupType.FULL:
        raise ValueError("Цепочка не содержит полной резервной копии")

    restored = {
        "users": 0,
        "settings": 0,
        "policies": 0,
        "sources": 0,
        "queries": 0,
        "audit_logs": 0,
    }
    for _, payload in reversed(chain):
        counts = _apply_backup_payload(db, payload)
        for key, value in counts.items():
            restored[key] += value
    record.status = "restored"
    record.restored_at = datetime.utcnow()
    write_audit(db, "backup_restore", "backup", record.id, user_id, restored)
    db.commit()
    cache.delete_pattern("dashboard:*")
    return restored
