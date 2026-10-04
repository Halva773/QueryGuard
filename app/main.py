from __future__ import annotations

import csv
import io
import logging
import math
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .analytics import dashboard_data, ensure_default_settings, serialize_snapshot
from .cache import cache
from .config import settings
from .database import Base, SessionLocal, engine, get_db
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
from .security import csrf_token, encrypt_secret, hash_password, validate_csrf, verify_password
from .services import (
    collect_source,
    create_backup,
    restore_backup,
    run_retention,
    seed_demo,
    test_source_connection,
    verify_backup,
    write_audit,
)


BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger("queryguard")


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.is_production and (
        settings.secret_key == "dev-secret-change-me"
        or settings.encryption_key == "dev-encryption-change-me"
    ):
        raise RuntimeError("В production необходимо задать SECRET_KEY и ENCRYPTION_KEY")
    Base.metadata.create_all(bind=engine)
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        seed_demo(db)
    yield


app = FastAPI(
    title="QueryGuard API",
    description="Система выявления ресурсоёмких запросов PostgreSQL в торговой сети",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="queryguard_session",
    max_age=8 * 60 * 60,
    same_site="lax",
    https_only=settings.session_https_only,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class LoginRequired(Exception):
    pass


class Forbidden(Exception):
    pass


@app.exception_handler(LoginRequired)
async def login_required_handler(request: Request, exc: LoginRequired) -> RedirectResponse:
    flash(request, "Сначала войдите в систему", "warning")
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(Forbidden)
async def forbidden_handler(request: Request, exc: Forbidden) -> HTMLResponse:
    user = None
    with SessionLocal() as db:
        user = get_current_user(request, db)
        return templates.TemplateResponse(
            request,
            "error.html",
            context(request, user, title="Доступ запрещён", status=403, message="У вашей роли нет прав на это действие."),
            status_code=403,
        )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException) -> HTMLResponse:
    with SessionLocal() as db:
        user = get_current_user(request, db)
        return templates.TemplateResponse(
            request,
            "error.html",
            context(request, user, title="Страница не найдена", status=404, message="Проверьте адрес или вернитесь на дашборд."),
            status_code=404,
        )


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": str(exc.detail)}, status_code=exc.status_code)
    messages = {
        400: "Проверьте введённые данные и повторите действие.",
        405: "Для этого адреса выбран неподдерживаемый способ запроса.",
    }
    with SessionLocal() as db:
        user = get_current_user(request, db)
        return templates.TemplateResponse(
            request,
            "error.html",
            context(
                request,
                user,
                title="Не удалось выполнить запрос",
                status=exc.status_code,
                message=messages.get(exc.status_code, str(exc.detail)),
            ),
            status_code=exc.status_code,
        )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error while processing %s", request.url.path)
    with SessionLocal() as db:
        user = get_current_user(request, db)
        return templates.TemplateResponse(
            request,
            "error.html",
            context(
                request,
                user,
                title="Внутренняя ошибка",
                status=500,
                message="Действие не выполнено. Повторите попытку или обратитесь к администратору.",
            ),
            status_code=500,
        )


def flash(request: Request, message: str, kind: str = "success") -> None:
    items = list(request.session.get("flashes", []))
    items.append({"message": message, "kind": kind})
    request.session["flashes"] = items[-5:]


def context(request: Request, user: Optional[User], **values: Any) -> dict[str, Any]:
    data = {
        "request": request,
        "app_name": settings.app_name,
        "current_user": user,
        "csrf_token": csrf_token(request.session),
        "flashes": request.session.pop("flashes", []),
        "roles": UserRole,
        "now": datetime.utcnow(),
        "cache_backend": cache.backend,
    }
    data.update(values)
    return data


def get_current_user(request: Request, db: Session) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = db.get(User, int(user_id))
    return user if user and user.is_active else None


def require_user(request: Request, db: Session) -> User:
    user = get_current_user(request, db)
    if not user:
        raise LoginRequired()
    return user


def require_roles(user: User, *roles: UserRole) -> None:
    if user.role not in roles:
        raise Forbidden()


def remote_ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def checked_form(request: Request) -> Any:
    form = await request.form()
    if not validate_csrf(request.session, form.get("csrf_token")):
        raise HTTPException(status_code=400, detail="Некорректный CSRF-токен")
    return form


def visible_sources_stmt(user: User):
    stmt = select(DataSource)
    if user.role == UserRole.OWNER:
        stmt = stmt.where(DataSource.owner_id == user.id)
    return stmt


@app.get("/health")
def health(db: Session = Depends(get_db)) -> JSONResponse:
    db.scalar(select(func.count(User.id)))
    return JSONResponse({"status": "ok", "database": "ok", "cache": cache.backend})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", context(request, None, title="Вход"))


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await checked_form(request)
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    if cache.hit_rate_limit(f"login:{remote_ip(request)}", 8, 300):
        flash(request, "Слишком много попыток. Повторите вход через несколько минут.", "danger")
        return RedirectResponse("/login", status_code=303)
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash) or not user.is_active:
        write_audit(db, "login_failed", "user", user.id if user else "", details={"username": username}, ip_address=remote_ip(request))
        db.commit()
        flash(request, "Неверный логин или пароль", "danger")
        return RedirectResponse("/login", status_code=303)
    request.session.clear()
    request.session["user_id"] = user.id
    csrf_token(request.session)
    cache.delete(f"login:{remote_ip(request)}")
    write_audit(db, "login", "user", user.id, user.id, ip_address=remote_ip(request))
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "register.html", context(request, None, title="Регистрация"))


@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    form = await checked_form(request)
    username = str(form.get("username", "")).strip().lower()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    if len(username) < 3 or "@" not in email:
        flash(request, "Укажите логин от 3 символов и корректный email", "danger")
        return RedirectResponse("/register", status_code=303)
    try:
        user = User(username=username, email=email, password_hash=hash_password(password), role=UserRole.OWNER)
        db.add(user)
        db.flush()
        write_audit(db, "register", "user", user.id, user.id, ip_address=remote_ip(request))
        db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        message = str(exc) if isinstance(exc, ValueError) else "Логин или email уже используются"
        flash(request, message, "danger")
        return RedirectResponse("/register", status_code=303)
    request.session["user_id"] = user.id
    flash(request, "Аккаунт создан")
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await checked_form(request)
    write_audit(db, "logout", "user", user.id, user.id, ip_address=remote_ip(request))
    db.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    data = dashboard_data(db, owner_id=user.id if user.role == UserRole.OWNER else None)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        context(request, user, title="Сводка", active="dashboard", data=data),
    )


@app.get("/queries", response_class=HTMLResponse)
def queries_page(
    request: Request,
    q: str = "",
    severity: str = "",
    source_id: Optional[int] = None,
    archived: str = "active",
    sort: str = "score_desc",
    page: int = 1,
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    page = max(page, 1)
    page_size = 20
    stmt = select(QuerySnapshot).join(QuerySnapshot.source)
    if archived == "archived":
        stmt = stmt.where(QuerySnapshot.is_archived.is_(True))
    elif archived != "all":
        archived = "active"
        stmt = stmt.where(QuerySnapshot.is_archived.is_(False))
    if user.role == UserRole.OWNER:
        stmt = stmt.where(DataSource.owner_id == user.id)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(QuerySnapshot.query_text.ilike(pattern), QuerySnapshot.db_user.ilike(pattern), DataSource.name.ilike(pattern))
        )
    if severity in {item.value for item in Severity}:
        stmt = stmt.where(QuerySnapshot.severity == Severity(severity))
    if source_id:
        stmt = stmt.where(QuerySnapshot.source_id == source_id)
    ordering = {
        "score_desc": desc(QuerySnapshot.toxicity_score),
        "mean_desc": desc(QuerySnapshot.mean_exec_time_ms),
        "io_desc": desc(QuerySnapshot.io_bytes_estimate),
        "calls_desc": desc(QuerySnapshot.calls),
        "date_desc": desc(QuerySnapshot.collected_at),
        "query_asc": asc(QuerySnapshot.query_text),
    }.get(sort, desc(QuerySnapshot.toxicity_score))
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = db.scalar(count_stmt) or 0
    items = db.scalars(stmt.order_by(ordering).offset((page - 1) * page_size).limit(page_size)).all()
    sources = db.scalars(visible_sources_stmt(user).order_by(DataSource.name)).all()
    return templates.TemplateResponse(
        request,
        "queries.html",
        context(
            request,
            user,
            title="Запросы",
            active="queries",
            items=items,
            sources=sources,
            filters={
                "q": q,
                "severity": severity,
                "source_id": source_id,
                "archived": archived,
                "sort": sort,
            },
            page=page,
            pages=max(1, math.ceil(total / page_size)),
            total=total,
        ),
    )


@app.get("/queries/{snapshot_id}", response_class=HTMLResponse)
def query_detail(snapshot_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    item = db.get(QuerySnapshot, snapshot_id)
    if not item or (user.role == UserRole.OWNER and item.source.owner_id != user.id):
        raise HTTPException(status_code=404)
    similar = db.scalars(
        (
            select(QuerySnapshot)
            .join(QuerySnapshot.source)
            .where(QuerySnapshot.fingerprint == item.fingerprint, QuerySnapshot.id != item.id)
            .where(DataSource.owner_id == user.id if user.role == UserRole.OWNER else True)
            .order_by(desc(QuerySnapshot.collected_at))
            .limit(8)
        )
    ).all()
    return templates.TemplateResponse(
        request,
        "query_detail.html",
        context(request, user, title=f"Запрос {item.query_id}", active="queries", item=item, similar=similar),
    )


@app.post("/queries/{snapshot_id}/archive")
async def archive_query(snapshot_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.STEWARD, UserRole.ADMIN)
    await checked_form(request)
    item = db.get(QuerySnapshot, snapshot_id)
    if not item:
        raise HTTPException(status_code=404)
    item.is_archived = True
    item.archived_at = datetime.utcnow()
    write_audit(db, "archive", "query_snapshot", item.id, user.id, ip_address=remote_ip(request))
    db.commit()
    cache.delete_pattern("dashboard:*")
    flash(request, "Снимок запроса перемещён в архив")
    return RedirectResponse("/queries", status_code=303)


@app.post("/queries/{snapshot_id}/unarchive")
async def unarchive_query(snapshot_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.STEWARD, UserRole.ADMIN)
    await checked_form(request)
    item = db.get(QuerySnapshot, snapshot_id)
    if not item:
        raise HTTPException(status_code=404)
    item.is_archived = False
    item.archived_at = None
    write_audit(db, "unarchive", "query_snapshot", item.id, user.id, ip_address=remote_ip(request))
    db.commit()
    cache.delete_pattern("dashboard:*")
    flash(request, "Снимок запроса возвращён из архива")
    return RedirectResponse(f"/queries/{snapshot_id}", status_code=303)


@app.post("/queries/{snapshot_id}/delete")
async def delete_query(snapshot_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    if form.get("confirm") != "yes":
        flash(request, "Удаление не выполнено: требуется подтверждение", "warning")
        return RedirectResponse(f"/queries/{snapshot_id}", status_code=303)
    item = db.get(QuerySnapshot, snapshot_id)
    if not item:
        raise HTTPException(status_code=404)
    write_audit(db, "delete", "query_snapshot", item.id, user.id, {"fingerprint": item.fingerprint}, remote_ip(request))
    db.delete(item)
    db.commit()
    cache.delete_pattern("dashboard:*")
    flash(request, "Снимок запроса удалён")
    return RedirectResponse("/queries", status_code=303)


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    sources = db.scalars(visible_sources_stmt(user).order_by(DataSource.name)).all()
    return templates.TemplateResponse(
        request,
        "sources.html",
        context(request, user, title="Источники", active="sources", sources=sources),
    )


@app.get("/sources/new", response_class=HTMLResponse)
def source_new_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.OWNER, UserRole.STEWARD, UserRole.ADMIN)
    return templates.TemplateResponse(
        request,
        "source_form.html",
        context(request, user, title="Новый источник", active="sources", source=None),
    )


@app.post("/sources/new")
async def source_create(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.OWNER, UserRole.STEWARD, UserRole.ADMIN)
    form = await checked_form(request)
    try:
        name = str(form.get("name", "")).strip()
        host = str(form.get("host", "")).strip()
        port = int(form.get("port", 5432))
        database_name = str(form.get("database_name", "")).strip()
        username = str(form.get("username", "")).strip()
        ssl_mode = str(form.get("ssl_mode", "prefer"))
        if not all([name, host, database_name, username]) or not 1 <= port <= 65535:
            raise ValueError
        if ssl_mode not in {"disable", "prefer", "require", "verify-ca", "verify-full"}:
            raise ValueError
        source = DataSource(
            name=name,
            kind="postgresql",
            host=host,
            port=port,
            database_name=database_name,
            username=username,
            password_encrypted=encrypt_secret(str(form.get("password", ""))),
            ssl_mode=ssl_mode,
            owner_id=user.id,
        )
        db.add(source)
        db.flush()
        write_audit(db, "create", "data_source", source.id, user.id, {"name": source.name}, remote_ip(request))
        db.commit()
    except (ValueError, IntegrityError):
        db.rollback()
        flash(request, "Проверьте поля: имя должно быть уникальным, порт — числом", "danger")
        return RedirectResponse("/sources/new", status_code=303)
    flash(request, "Источник добавлен. Проверьте подключение перед сбором.")
    return RedirectResponse("/sources", status_code=303)


@app.get("/sources/{source_id}/edit", response_class=HTMLResponse)
def source_edit_page(source_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    source = db.get(DataSource, source_id)
    if not source or (user.role == UserRole.OWNER and source.owner_id != user.id):
        raise HTTPException(status_code=404)
    require_roles(user, UserRole.OWNER, UserRole.STEWARD, UserRole.ADMIN)
    return templates.TemplateResponse(
        request,
        "source_form.html",
        context(request, user, title="Редактирование источника", active="sources", source=source),
    )


@app.post("/sources/{source_id}/edit")
async def source_edit(source_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.OWNER, UserRole.STEWARD, UserRole.ADMIN)
    source = db.get(DataSource, source_id)
    if not source or (user.role == UserRole.OWNER and source.owner_id != user.id):
        raise HTTPException(status_code=404)
    form = await checked_form(request)
    try:
        source.name = str(form.get("name", "")).strip()
        source.host = str(form.get("host", "")).strip()
        source.port = int(form.get("port", 5432))
        source.database_name = str(form.get("database_name", "")).strip()
        source.username = str(form.get("username", "")).strip()
        source.ssl_mode = str(form.get("ssl_mode", "prefer"))
        if not all([source.name, source.host, source.database_name, source.username]):
            raise ValueError
        if not 1 <= source.port <= 65535:
            raise ValueError
        if source.ssl_mode not in {"disable", "prefer", "require", "verify-ca", "verify-full"}:
            raise ValueError
    except ValueError:
        flash(request, "Проверьте обязательные поля и порт источника", "danger")
        return RedirectResponse(f"/sources/{source_id}/edit", status_code=303)
    source.is_active = form.get("is_active") == "on"
    if form.get("password"):
        source.password_encrypted = encrypt_secret(str(form.get("password")))
    try:
        write_audit(db, "update", "data_source", source.id, user.id, {"name": source.name}, remote_ip(request))
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "Источник с таким названием уже существует", "danger")
        return RedirectResponse(f"/sources/{source_id}/edit", status_code=303)
    flash(request, "Источник обновлён")
    return RedirectResponse("/sources", status_code=303)


@app.post("/sources/{source_id}/test")
async def source_test(source_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.OWNER, UserRole.STEWARD, UserRole.ADMIN)
    await checked_form(request)
    source = db.get(DataSource, source_id)
    if not source or (user.role == UserRole.OWNER and source.owner_id != user.id):
        raise HTTPException(status_code=404)
    ok, message = test_source_connection(source)
    write_audit(db, "connection_test", "data_source", source.id, user.id, {"ok": ok}, remote_ip(request))
    db.commit()
    flash(request, message, "success" if ok else "danger")
    return RedirectResponse("/sources", status_code=303)


@app.post("/sources/{source_id}/collect")
async def source_collect(source_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.STEWARD, UserRole.ADMIN)
    await checked_form(request)
    source = db.get(DataSource, source_id)
    if not source:
        raise HTTPException(status_code=404)
    try:
        count = collect_source(db, source, user.id, remote_ip(request))
        flash(request, f"Сбор завершён: сохранено снимков запросов — {count}")
    except RuntimeError as exc:
        db.rollback()
        flash(request, str(exc), "danger")
    return RedirectResponse("/sources", status_code=303)


@app.post("/sources/{source_id}/delete")
async def source_delete(source_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    if form.get("confirm") != "yes":
        flash(request, "Удаление источника требует явного подтверждения", "warning")
        return RedirectResponse("/sources", status_code=303)
    source = db.get(DataSource, source_id)
    if not source:
        raise HTTPException(status_code=404)
    write_audit(db, "delete", "data_source", source.id, user.id, {"name": source.name}, remote_ip(request))
    db.delete(source)
    db.commit()
    cache.delete_pattern("dashboard:*")
    flash(request, "Источник и связанные снимки удалены")
    return RedirectResponse("/sources", status_code=303)


@app.get("/lifecycle", response_class=HTMLResponse)
def lifecycle_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    policies = db.scalars(select(RetentionPolicy).order_by(RetentionPolicy.name)).all()
    backups = db.scalars(select(BackupRecord).order_by(desc(BackupRecord.created_at)).limit(20)).all()
    system_settings = db.scalars(select(SystemSetting).order_by(SystemSetting.key)).all()
    return templates.TemplateResponse(
        request,
        "lifecycle.html",
        context(
            request,
            user,
            title="Жизненный цикл",
            active="lifecycle",
            policies=policies,
            backups=backups,
            settings_rows=system_settings,
        ),
    )


@app.post("/lifecycle/policies/{policy_id}")
async def update_policy(policy_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.STEWARD, UserRole.ADMIN)
    form = await checked_form(request)
    policy = db.get(RetentionPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404)
    try:
        archive_days = int(form.get("archive_after_days", 90))
        delete_days = int(form.get("delete_after_days", 365))
    except (TypeError, ValueError):
        flash(request, "Сроки хранения должны быть целыми числами", "danger")
        return RedirectResponse("/lifecycle", status_code=303)
    if archive_days < 1 or delete_days <= archive_days:
        flash(request, "Срок удаления должен быть больше срока архивирования", "danger")
        return RedirectResponse("/lifecycle", status_code=303)
    policy.archive_after_days = archive_days
    policy.delete_after_days = delete_days
    policy.enabled = form.get("enabled") == "on"
    write_audit(db, "update", "retention_policy", policy.id, user.id)
    db.commit()
    flash(request, "Политика хранения обновлена")
    return RedirectResponse("/lifecycle", status_code=303)


@app.post("/lifecycle/run")
async def retention_run(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    result = run_retention(db, user.id, confirm_delete=form.get("confirm_delete") == "yes")
    flash(request, f"Архивировано: {result['archived']}; удалено: {result['deleted']}")
    return RedirectResponse("/lifecycle", status_code=303)


@app.post("/lifecycle/settings")
async def settings_update(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    try:
        for key in ["cpu_power_w", "io_kwh_per_gb", "electricity_rub_per_kwh", "storage_rub_per_gb_month", "dark_query_days"]:
            value = str(form.get(key, "")).replace(",", ".")
            if float(value) < 0:
                raise ValueError
            row = db.get(SystemSetting, key)
            if row:
                row.value = value
    except (TypeError, ValueError):
        db.rollback()
        flash(request, "Удельные показатели должны быть неотрицательными числами", "danger")
        return RedirectResponse("/lifecycle", status_code=303)
    write_audit(db, "update", "system_settings", user_id=user.id)
    db.commit()
    cache.delete_pattern("dashboard:*")
    flash(request, "Удельные показатели обновлены")
    return RedirectResponse("/lifecycle", status_code=303)


@app.post("/backups/create")
async def backup_create(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    kind = BackupType.INCREMENTAL if form.get("backup_type") == "incremental" else BackupType.FULL
    try:
        record = create_backup(db, kind, user.id)
    except ValueError as exc:
        flash(request, str(exc), "warning")
        return RedirectResponse("/lifecycle", status_code=303)
    flash(request, f"Резервная копия #{record.id} создана. Выполните проверку целостности.")
    return RedirectResponse("/lifecycle", status_code=303)


@app.post("/backups/{backup_id}/verify")
async def backup_verify(backup_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN, UserRole.AUDITOR)
    await checked_form(request)
    record = db.get(BackupRecord, backup_id)
    if not record:
        raise HTTPException(status_code=404)
    valid = verify_backup(db, record, user.id)
    flash(request, "Целостность подтверждена" if valid else "Копия повреждена", "success" if valid else "danger")
    return RedirectResponse("/lifecycle", status_code=303)


@app.post("/backups/{backup_id}/restore")
async def backup_restore(backup_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    form = await checked_form(request)
    if form.get("confirm") != "yes":
        flash(request, "Восстановление требует подтверждения администратора", "warning")
        return RedirectResponse("/lifecycle", status_code=303)
    record = db.get(BackupRecord, backup_id)
    if not record:
        raise HTTPException(status_code=404)
    try:
        result = restore_backup(db, record, user.id)
        flash(request, "Восстановление проверено: " + ", ".join(f"{k}={v}" for k, v in result.items()))
    except ValueError as exc:
        flash(request, str(exc), "danger")
    return RedirectResponse("/lifecycle", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, action: str = "", page: int = 1, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN, UserRole.AUDITOR)
    page = max(page, 1)
    stmt = select(AuditLog).order_by(desc(AuditLog.created_at))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    logs = db.scalars(stmt.offset((page - 1) * 30).limit(30)).all()
    actions = db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)).all()
    return templates.TemplateResponse(
        request,
        "audit.html",
        context(
            request,
            user,
            title="Журнал аудита",
            active="audit",
            logs=logs,
            actions=actions,
            selected_action=action,
            page=page,
            pages=max(1, math.ceil(total / 30)),
        ),
    )


@app.get("/audit.csv")
def audit_export(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN, UserRole.AUDITOR)
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(5000)).all()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "timestamp", "user", "action", "entity_type", "entity_id", "details"])
    for row in rows:
        writer.writerow([row.id, row.created_at.isoformat(), row.user.username if row.user else "system", row.action, row.entity_type, row.entity_id, row.details])
    write_audit(db, "export", "audit_log", user_id=user.id, details={"rows": len(rows)}, ip_address=remote_ip(request))
    db.commit()
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=audit.csv"})


@app.get("/queries.csv")
def query_export(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN, UserRole.AUDITOR, UserRole.STEWARD)
    stmt = select(QuerySnapshot).join(QuerySnapshot.source).order_by(desc(QuerySnapshot.toxicity_score)).limit(5000)
    rows = db.scalars(stmt).all()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["source", "query_id", "collected_at", "score", "severity", "mean_ms", "calls", "io_bytes", "energy_kwh", "cost_rub", "query"])
    for row in rows:
        writer.writerow([row.source.name, row.query_id, row.collected_at.isoformat(), row.toxicity_score, row.severity.value, row.mean_exec_time_ms, row.calls, row.io_bytes_estimate, row.energy_kwh, row.cost_rub, row.query_text])
    write_audit(db, "export", "query_snapshots", user_id=user.id, details={"rows": len(rows)}, ip_address=remote_ip(request))
    db.commit()
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=query-report.csv"})


@app.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_roles(user, UserRole.ADMIN)
    users = db.scalars(select(User).order_by(User.username)).all()
    return templates.TemplateResponse(
        request,
        "users.html",
        context(request, user, title="Пользователи", active="users", users=users),
    )


@app.post("/admin/users/{user_id}")
async def user_update(user_id: int, request: Request, db: Session = Depends(get_db)):
    admin = require_user(request, db)
    require_roles(admin, UserRole.ADMIN)
    form = await checked_form(request)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    if target.id == admin.id and form.get("is_active") != "on":
        flash(request, "Нельзя отключить собственную учётную запись", "danger")
        return RedirectResponse("/admin/users", status_code=303)
    try:
        target.role = UserRole(str(form.get("role")))
    except ValueError:
        raise HTTPException(status_code=400, detail="Неизвестная роль")
    target.is_active = form.get("is_active") == "on"
    write_audit(db, "role_change", "user", target.id, admin.id, {"role": target.role.value, "active": target.is_active}, remote_ip(request))
    db.commit()
    flash(request, f"Права пользователя {target.username} обновлены")
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    author = {
        "name": settings.author_name,
        "group": settings.author_group,
        "contact": settings.author_contact,
        "experience": settings.author_experience,
        "started_at": settings.project_started_at,
        "finished_at": settings.project_finished_at,
    }
    return templates.TemplateResponse(
        request,
        "about.html",
        context(request, user, title="Об авторе", active="about", author=author),
    )


@app.get("/api/v1/dashboard")
def api_dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    return JSONResponse(
        dashboard_data(db, owner_id=user.id if user.role == UserRole.OWNER else None)
    )


@app.get("/api/v1/queries")
def api_queries(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    user = require_user(request, db)
    limit = min(max(limit, 1), 200)
    stmt = select(QuerySnapshot).join(QuerySnapshot.source).order_by(desc(QuerySnapshot.toxicity_score)).limit(limit)
    if user.role == UserRole.OWNER:
        stmt = stmt.where(DataSource.owner_id == user.id)
    return JSONResponse({"items": [serialize_snapshot(item) for item in db.scalars(stmt).all()]})
