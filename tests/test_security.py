from __future__ import annotations

import pytest

from app.security import decrypt_secret, encrypt_secret, hash_password, verify_password


def test_password_hash_is_salted_and_verifiable():
    first = hash_password("StrongPassword123!")
    second = hash_password("StrongPassword123!")

    assert first != second
    assert "StrongPassword123!" not in first
    assert verify_password("StrongPassword123!", first)
    assert not verify_password("WrongPassword", first)


def test_password_policy():
    with pytest.raises(ValueError):
        hash_password("short")
    with pytest.raises(ValueError):
        hash_password("x" * 257)


def test_source_secret_round_trip():
    encrypted = encrypt_secret("postgres-password")
    assert encrypted != "postgres-password"
    assert decrypt_secret(encrypted) == "postgres-password"
