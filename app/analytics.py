from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from .cache import cache
from .models import DataSource, QuerySnapshot, Severity, SystemSetting, User


BLOCK_SIZE = 8192


DEFAULT_SETTINGS = {
    "cpu_power_w": ("65", "Оценочная мощность CPU, Вт"),
    "io_kwh_per_gb": ("0.0005", "Энергия на обработку 1 ГБ I/O, кВт·ч"),
    "electricity_rub_per_kwh": ("7.0", "Стоимость электроэнергии, ₽/кВт·ч"),
    "storage_rub_per_gb_month": ("3.5", "Стоимость хранения, ₽/ГБ в месяц"),
    "dark_query_days": ("30", "Период неактивности шаблона запроса, дней"),
}


def normalize_query(query: str) -> str:
    value = re.sub(r"--.*?$|/\*.*?\*/", " ", query, flags=re.M | re.S)
    value = re.sub(r"\$\$.*?\$\$", "?", value, flags=re.S)
    value = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)\$.*?\$\1\$", "?", value, flags=re.S)
    value = re.sub(r"'(?:''|[^'])*'", "?", value)
    value = re.sub(r"\$\d+", "?", value)
    value = re.sub(r"\b\d+(?:\.\d+)?\b", "?", value)
    value = re.sub(r"\s+", " ", value).strip().lower()
    value = re.sub(r"\s*([(),=<>])\s*", r"\1", value)
    return value


def query_fingerprint(query: str) -> str:
    return hashlib.sha256(normalize_query(query).encode("utf-8")).hexdigest()


def calculate_toxicity(row: dict[str, Any]) -> tuple[float, Severity, dict[str, float]]:
    mean_ms = float(row.get("mean_exec_time_ms") or 0)
    total_ms = float(row.get("total_exec_time_ms") or 0)
    hit = float(row.get("shared_blks_hit") or 0)
    read = float(row.get("shared_blks_read") or 0)
    written = float(row.get("shared_blks_written") or 0)
    temp = float(row.get("temp_blks_written") or 0)
    wal = float(row.get("wal_bytes") or 0)
    cache_ratio = hit / max(hit + read, 1)
    shared_io_bytes = (read + written) * BLOCK_SIZE
    io_bytes = (read + written + temp) * BLOCK_SIZE
    parts = {
        "latency": min(mean_ms / 5000, 1),
        "total_time": min(total_ms / 600000, 1),
        "io": min(shared_io_bytes / (2 * 1024**3), 1),
        "spill": min((temp * BLOCK_SIZE) / (512 * 1024**2), 1),
        "cache_penalty": max(0, 1 - cache_ratio),
        "wal": min(wal / (1024**3), 1),
    }
    score = 100 * (
        0.25 * parts["latency"]
        + 0.20 * parts["total_time"]
        + 0.20 * parts["io"]
        + 0.15 * parts["spill"]
        + 0.10 * parts["cache_penalty"]
        + 0.10 * parts["wal"]
    )
    score = round(min(max(score, 0), 100), 2)
    severity = (
        Severity.CRITICAL
        if score >= 75
        else Severity.HIGH
        if score >= 50
        else Severity.MEDIUM
        if score >= 25
        else Severity.LOW
    )
    parts["cache_hit_ratio"] = cache_ratio
    parts["shared_io_bytes"] = shared_io_bytes
    parts["io_bytes"] = io_bytes
    return score, severity, parts


def estimate_impact(db: Session, total_ms: float, io_bytes: int) -> tuple[float, float]:
    values = get_setting_values(db)
    cpu_kwh = total_ms / 1000 / 3600 * (values["cpu_power_w"] / 1000)
    io_kwh = (io_bytes / 1024**3) * values["io_kwh_per_gb"]
    energy = max(cpu_kwh + io_kwh, 0)
    return round(energy, 8), round(energy * values["electricity_rub_per_kwh"], 4)


def ensure_default_settings(db: Session) -> None:
    existing = {row.key for row in db.scalars(select(SystemSetting)).all()}
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if key not in existing:
            db.add(SystemSetting(key=key, value=value, description=description))
    db.commit()


def get_setting_values(db: Session) -> dict[str, float]:
    values = {key: float(value) for key, (value, _) in DEFAULT_SETTINGS.items()}
    for row in db.scalars(select(SystemSetting)).all():
        try:
            values[row.key] = float(row.value)
        except ValueError:
            continue
    return values


def _recommendations(snapshots: list[QuerySnapshot]) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    if not snapshots:
        return recs
    worst = snapshots[0]
    if worst.temp_blks_written > 0:
        recs.append({
            "level": "high",
            "title": "Уменьшить временные выгрузки",
            "text": "Проверьте сортировки и HASH JOIN; запрос пишет временные блоки на диск.",
            "effect": f"до {worst.temp_blks_written * BLOCK_SIZE / 1024**2:.1f} МБ I/O за снимок",
        })
    low_cache = [q for q in snapshots if q.cache_hit_ratio < 0.9]
    if low_cache:
        recs.append({
            "level": "medium",
            "title": "Повысить селективность чтения",
            "text": "Добавьте или уточните индексы для запросов с низкой долей попаданий в кэш.",
            "effect": f"затронуто запросов: {len(low_cache)}",
        })
    repeated_versions = len(snapshots) - len({q.fingerprint for q in snapshots})
    if repeated_versions > 0:
        recs.append({
            "level": "low",
            "title": "Стабилизировать повторяющиеся шаблоны",
            "text": "Тяжёлые шаблоны повторяются в нескольких снимках; сравните план после оптимизации.",
            "effect": f"исторических версий: {repeated_versions}",
        })
    if not recs:
        recs.append({
            "level": "low",
            "title": "Сохранить текущий профиль",
            "text": "Критических отклонений нет; продолжайте сравнивать динамику после релизов.",
            "effect": "контроль без изменений",
        })
    return recs[:3]


def dashboard_data(
    db: Session, use_cache: bool = True, owner_id: int | None = None
) -> dict[str, Any]:
    key = f"dashboard:v2:{owner_id if owner_id is not None else 'all'}"
    if use_cache:
        cached = cache.get_json(key)
        if cached:
            return cached

    cutoff = datetime.utcnow() - timedelta(days=7)
    snapshot_stmt = select(QuerySnapshot).where(
        QuerySnapshot.collected_at >= cutoff,
        QuerySnapshot.is_archived.is_(False),
    )
    if owner_id is not None:
        snapshot_stmt = snapshot_stmt.join(QuerySnapshot.source).where(
            DataSource.owner_id == owner_id
        )
    snapshots = db.scalars(
        snapshot_stmt.order_by(desc(QuerySnapshot.toxicity_score)).limit(500)
    ).all()
    total_exec = sum(q.total_exec_time_ms for q in snapshots)
    weighted = sum(q.toxicity_score * max(q.total_exec_time_ms, 1) for q in snapshots)
    toxicity = weighted / max(total_exec, len(snapshots), 1)
    eco_index = round(100 - toxicity, 1)
    energy = sum(q.energy_kwh for q in snapshots)
    cost = sum(q.cost_rub for q in snapshots)
    io_bytes = sum(q.io_bytes_estimate for q in snapshots)

    buckets: dict[date, list[tuple[float, float]]] = defaultdict(list)
    for q in snapshots:
        buckets[q.collected_at.date()].append(
            (q.toxicity_score, max(q.total_exec_time_ms, 1))
        )
    trend = [
        {
            "label": day.strftime("%d.%m"),
            "value": round(
                sum(score * weight for score, weight in values)
                / sum(weight for _, weight in values),
                1,
            ),
        }
        for day, values in sorted(buckets.items())
    ][-7:]
    severity_counts = {severity.value: 0 for severity in Severity}
    for q in snapshots:
        severity_counts[q.severity.value] += 1

    result = {
        "eco_index": eco_index,
        "toxicity": round(toxicity, 1),
        "total_queries": len(snapshots),
        "critical_queries": severity_counts["critical"],
        "energy_kwh": round(energy, 5),
        "cost_rub": round(cost, 2),
        "io_gb": round(io_bytes / 1024**3, 3),
        "users": db.scalar(select(func.count(User.id))) or 0,
        "sources": db.scalar(
            select(func.count(DataSource.id)).where(
                DataSource.owner_id == owner_id if owner_id is not None else True
            )
        ) or 0,
        "trend": trend,
        "severity_counts": severity_counts,
        "top_queries": [serialize_snapshot(q) for q in snapshots[:8]],
        "recommendations": _recommendations(snapshots),
        "cache_backend": cache.backend,
        "generated_at": datetime.utcnow().isoformat(),
    }
    cache.set_json(key, result, ttl=30)
    return result


def serialize_snapshot(q: QuerySnapshot) -> dict[str, Any]:
    return {
        "id": q.id,
        "source": q.source.name if q.source else "—",
        "query_id": q.query_id,
        "query": q.query_text,
        "short_query": (q.query_text[:116] + "…") if len(q.query_text) > 116 else q.query_text,
        "calls": q.calls,
        "mean_ms": round(q.mean_exec_time_ms, 2),
        "total_ms": round(q.total_exec_time_ms, 2),
        "io_mb": round(q.io_bytes_estimate / 1024**2, 2),
        "cache_hit": round(q.cache_hit_ratio * 100, 1),
        "energy_kwh": q.energy_kwh,
        "cost_rub": q.cost_rub,
        "score": round(q.toxicity_score, 1),
        "severity": q.severity.value,
        "collected_at": q.collected_at.isoformat(),
    }
