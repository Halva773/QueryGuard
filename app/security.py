from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Пароль должен содержать не менее 8 символов")
    if len(password) > 256:
        raise ValueError("Пароль не должен быть длиннее 256 символов")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return "scrypt$16384$8$1${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    if len(password) > 256:
        return False
    try:
        algorithm, n, r, p, salt_b64, digest_b64 = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, binascii.Error):
        return False


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.encryption_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("Не удалось расшифровать пароль источника") from exc


def csrf_token(session: dict) -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf(session: dict, submitted: Optional[str]) -> bool:
    expected = session.get("csrf_token", "")
    return bool(expected and submitted and hmac.compare_digest(expected, submitted))
