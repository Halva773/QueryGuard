from __future__ import annotations

from sqlalchemy import select

from app.cache import cache
from app.models import DataSource, QuerySnapshot, Severity, User
from tests.conftest import csrf_from, login


def test_anonymous_user_is_redirected(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_admin_can_open_dashboard_and_api(client):
    login(client, "admin", "Admin123!")

    page = client.get("/")
    api = client.get("/api/v1/dashboard")

    assert page.status_code == 200
    assert "Сводка нагрузки" in page.text
    assert api.status_code == 200
    assert 0 <= api.json()["eco_index"] <= 100
    assert api.json()["total_queries"] > 0


def test_all_admin_pages_render(client, db):
    snapshot_id = db.scalar(select(QuerySnapshot.id))
    login(client, "admin", "Admin123!")

    paths = [
        "/",
        "/queries",
        f"/queries/{snapshot_id}",
        "/sources",
        "/sources/new",
        "/lifecycle",
        "/audit",
        "/admin/users",
        "/about",
    ]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path
        assert "QueryGuard" in response.text, path


def test_roles_are_enforced(client):
    login(client, "owner", "Owner123!")
    assert client.get("/audit").status_code == 403
    assert client.get("/admin/users").status_code == 403

    client.cookies.clear()
    login(client, "auditor", "Auditor123!")
    assert client.get("/audit").status_code == 200
    assert client.get("/admin/users").status_code == 403

    client.cookies.clear()
    login(client, "admin", "Admin123!")
    assert client.get("/admin/users").status_code == 200


def test_owner_api_does_not_expose_another_owners_queries(client, db):
    admin = db.scalar(select(User).where(User.username == "admin"))
    foreign_source = DataSource(
        name="Служебная база администратора",
        kind="demo",
        host="demo",
        port=5432,
        database_name="private_admin_db",
        username="admin",
        owner_id=admin.id,
    )
    db.add(foreign_source)
    db.flush()
    db.add(
        QuerySnapshot(
            source_id=foreign_source.id,
            query_id="private-query",
            fingerprint="f" * 64,
            query_text="SELECT private_admin_marker FROM internal_table",
            normalized_query="select private_admin_marker from internal_table",
            toxicity_score=99,
            severity=Severity.CRITICAL,
        )
    )
    db.commit()
    cache.delete_pattern("dashboard:*")

    login(client, "owner", "Owner123!")
    query_payload = client.get("/api/v1/queries?limit=200").json()
    dashboard_payload = client.get("/api/v1/dashboard").json()

    assert all(item["source"] != foreign_source.name for item in query_payload["items"])
    assert all(item["source"] != foreign_source.name for item in dashboard_payload["top_queries"])


def test_invalid_csrf_returns_informative_page(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "Admin123!", "csrf_token": "invalid"},
    )
    assert response.status_code == 400
    assert "Проверьте введённые данные" in response.text


def test_admin_can_archive_and_restore_snapshot(client, db):
    snapshot = db.scalar(select(QuerySnapshot))
    login(client, "admin", "Admin123!")
    detail = client.get(f"/queries/{snapshot.id}")
    token = csrf_from(detail)

    archived = client.post(
        f"/queries/{snapshot.id}/archive",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert archived.status_code == 303
    db.expire_all()
    assert db.get(QuerySnapshot, snapshot.id).is_archived
    assert snapshot.query_text[:40] in client.get("/queries?archived=archived").text

    restored = client.post(
        f"/queries/{snapshot.id}/unarchive",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert restored.status_code == 303
    db.expire_all()
    assert not db.get(QuerySnapshot, snapshot.id).is_archived
