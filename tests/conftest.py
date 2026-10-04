from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_ROOT = Path(tempfile.mkdtemp(prefix="queryguard-tests-"))
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'queryguard-test.db'}"
os.environ["REDIS_URL"] = "redis://127.0.0.1:1/15"
os.environ["BACKUP_DIR"] = str(TEST_ROOT / "backups")
os.environ["SECRET_KEY"] = "test-session-secret"
os.environ["ENCRYPTION_KEY"] = "test-encryption-secret"
os.environ["SEED_DEMO"] = "true"

from app.cache import cache  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services import seed_demo  # noqa: E402


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    cache.delete_pattern("*")
    with SessionLocal() as db:
        seed_demo(db)
    yield


@pytest.fixture()
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "CSRF-токен не найден в HTML"
    return match.group(1)


def login(client: TestClient, username: str, password: str) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_from(page)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
