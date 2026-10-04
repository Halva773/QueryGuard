from __future__ import annotations

from sqlalchemy import select

from app.models import BackupType, QuerySnapshot, SystemSetting, User
from app.services import create_backup, restore_backup, verify_backup


def test_full_backup_verify_and_restore(db):
    admin = db.scalar(select(User).where(User.username == "admin"))
    setting = db.get(SystemSetting, "cpu_power_w")
    original = setting.value
    snapshot = db.scalar(select(QuerySnapshot))
    snapshot_id = snapshot.id

    record = create_backup(db, BackupType.FULL, admin.id)
    assert record.size_bytes > 0
    assert verify_backup(db, record, admin.id)

    setting.value = "999"
    db.delete(snapshot)
    db.commit()
    result = restore_backup(db, record, admin.id)
    db.refresh(setting)

    assert setting.value == original
    assert result["settings"] > 0
    assert result["queries"] > 0
    assert db.get(QuerySnapshot, snapshot_id) is not None
    assert record.status == "restored"


def test_incremental_backup_has_verified_parent(db):
    admin = db.scalar(select(User).where(User.username == "admin"))
    full = create_backup(db, BackupType.FULL, admin.id)
    assert verify_backup(db, full, admin.id)

    setting = db.get(SystemSetting, "electricity_rub_per_kwh")
    setting.value = "8.25"
    db.commit()
    incremental = create_backup(db, BackupType.INCREMENTAL, admin.id)

    assert incremental.parent_backup_id == full.id
    assert verify_backup(db, incremental, admin.id)


def test_corrupt_backup_is_rejected(db):
    admin = db.scalar(select(User).where(User.username == "admin"))
    record = create_backup(db, BackupType.FULL, admin.id)
    with open(record.file_path, "ab") as stream:
        stream.write(b"corruption")

    assert not verify_backup(db, record, admin.id)
    assert record.status == "corrupt"
