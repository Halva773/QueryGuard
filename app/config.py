from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "QueryGuard")
    app_env: str = os.getenv("APP_ENV", "development")
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-change-me")
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "dev-encryption-change-me")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./queryguard.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    backup_dir: Path = Path(os.getenv("BACKUP_DIR", "./data/backups"))
    seed_demo: bool = _as_bool(os.getenv("SEED_DEMO"), True)
    demo_admin_password: str = os.getenv("DEMO_ADMIN_PASSWORD", "Admin123!")
    session_https_only: bool = _as_bool(os.getenv("SESSION_HTTPS_ONLY"), False)
    author_name: str = os.getenv("AUTHOR_NAME", "Укажите ФИО")
    author_group: str = os.getenv("AUTHOR_GROUP", "Укажите группу и учебное заведение")
    author_contact: str = os.getenv("AUTHOR_CONTACT", "Укажите контактные данные")
    author_experience: str = os.getenv(
        "AUTHOR_EXPERIENCE", "Python, PostgreSQL, Redis, SQLAlchemy, FastAPI"
    )
    project_started_at: str = os.getenv("PROJECT_STARTED_AT", "2026-10-04")
    project_finished_at: str = os.getenv("PROJECT_FINISHED_AT", "")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


settings = Settings()

