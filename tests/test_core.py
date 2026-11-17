import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from kayralrics_vault.core import (
    Vault, VaultError, WrongPassword, IntegrityError, restore_encrypted_backup,
    _safe_archive_relative,
)

PASSWORD = "correct horse battery stable 2026"


def test_notes_events_lock_and_wrong_password(tmp_path):
    root = tmp_path / "vault"
    vault = Vault.create(root, PASSWORD)
    with pytest.raises(VaultError):
        Vault.create(root, PASSWORD)
    with pytest.raises(VaultError, match="already open"):
        Vault.open(root, PASSWORD)
    identity = vault.create_note("My private project")
    assert vault.note(identity)["body"] == ""
    assert vault.save_note(identity, "My private project", "Sensitive words ☀️")
    assert not vault.save_note(identity, "My private project", "Sensitive words ☀️")
    assert vault.note(identity)["body"] == "Sensitive words ☀️"
    assert vault.note(identity)["created_at"]
    assert vault.note(identity)["updated_at"]
    assert any(l["action"] == "note_updated" for l in vault.logs())
    raw = (root / "index.vlt").read_bytes()
    assert b"Sensitive words" not in raw
    assert b"My private project" not in raw
    vault.move_to_trash("note", identity)
    assert not vault.list_notes()
    assert vault.list_notes(True)[0]["id"] == identity
    vault.restore("note", identity)
    assert vault.list_notes()[0]["id"] == identity
    vault.move_to_trash("note", identity)
    vault.permanently_delete("note", identity)
    assert not vault.list_notes(True)
    assert any(l["action"] == "note_purged" for l in vault.logs())
    vault.lock()
    with pytest.raises(VaultError):
        vault.list_notes()
    with pytest.raises(WrongPassword):
        Vault.open(root, "this is the wrong password")
    reloaded = Vault.open(root, PASSWORD)
    assert not reloaded.list_notes()
    assert any(l["action"] == "vault_locked" for l in reloaded.logs())
    assert any(l["action"] == "vault_unlocked" for l in reloaded.logs())


def test_file_copy_and_corruption_detection(tmp_path):
    root = tmp_path / "vault"
    source = tmp_path / "Downloads" / "holiday_video.mp4"
    source.parent.mkdir()
    content = b"my sensitive video bytes" * 40000
    source.write_bytes(content)
    vault = Vault.create(root, PASSWORD)
    identity = vault.import_file(source)
    source.unlink()  # Must remain in the vault independent of Downloads.
    assert vault.file_bytes(identity, len(content) + 1) == content
    raw = (root / "blobs" / f"{identity}.bin").read_bytes()
    assert b"my sensitive video bytes" not in raw
    assert raw.startswith(b"KVB1")
    exported = tmp_path / "exported.mp4"
    vault.export_file(identity, exported)
    assert exported.read_bytes() == content
    assert vault.verify() == (1, [])
    blob_path = root / "blobs" / f"{identity}.bin"
    raw = bytearray(blob_path.read_bytes())
    raw[100] ^= 0x01
    blob_path.write_bytes(raw)
    with pytest.raises(IntegrityError):
        vault.file_bytes(identity, len(content) + 1)
    assert vault.verify()[1]
    prev = exported.read_bytes()
    with pytest.raises(IntegrityError):
        vault.export_file(identity, exported)
    assert exported.read_bytes() == prev  # Atomic export did not replace valid copy.


def test_import_folder_backup_restore_readable(tmp_path):
    project = tmp_path / "sample_project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.py").write_text("print('abc')\n")
    (project / "README.md").write_text("Project readme")
    vault = Vault.create(tmp_path / "original", PASSWORD)
    vault.create_note("Trip note")
    count, errors = vault.import_folder(project)
    assert count == 2 and errors == []
    assert sorted(v["path"] for v in vault.list_files()) == [
        "sample_project/README.md", "sample_project/src/main.py"]
    readable = tmp_path / "readable.zip"
    vault.export_readable_zip(readable)
    with zipfile.ZipFile(readable) as z:
        assert "files/sample_project/src/main.py" in z.namelist()
        assert z.read("files/sample_project/src/main.py") == b"print('abc')\n"
        assert "logs.json" in z.namelist()
        assert any(name.startswith("notes/") for name in z.namelist())
    vault.move_to_trash("file", vault.list_files()[0]["id"])
    for suffix in ["zip", "tar.gz", "tar"]:
        file = tmp_path / f"backup.{suffix}"
        vault.export_encrypted_backup(file)
        with (zipfile.ZipFile(file) if suffix == "zip" else tarfile.open(file, "r:gz" if suffix == "tar.gz" else "r")) as archive:
            names = archive.namelist() if suffix == "zip" else archive.getnames()
            assert "manifest.json" in names
            assert "index.vlt" in names
            assert len([x for x in names if x.startswith("blobs/")]) == 2
        dest = tmp_path / f"restored-{suffix.replace('.', '-') }"
        restore_encrypted_backup(file, dest)
        with pytest.raises(WrongPassword):
            Vault.open(dest, "bad password")
        reopened = Vault.open(dest, PASSWORD)
        assert len(reopened.list_files()) == 1
        assert len(reopened.list_files(True)) == 1
        assert len(reopened.list_notes()) == 1
        assert reopened.verify() == (2, [])
        reopened.lock()


def test_backup_archive_malicious_paths_rejected(tmp_path):
    source = tmp_path / "poison.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("../evil.txt", "malicious")
    out = tmp_path / "out"
    with pytest.raises(VaultError):
        restore_encrypted_backup(source, out)
    assert not out.exists()
    assert not (tmp_path / "evil.txt").exists()
    for name in ["../../secret", "/tmp/a", "foo/../bar", "C:/windows", "dir\\name"]:
        with pytest.raises(VaultError):
            _safe_archive_relative(name)


def test_minimum_password_and_do_not_overwrite(tmp_path):
    with pytest.raises(VaultError):
        Vault.create(tmp_path / "one", "short")
    root = tmp_path / "other"
    Vault.create(root, PASSWORD)
    with pytest.raises(VaultError):
        Vault.create(root, PASSWORD)


def test_exclusive_writer_and_snapshot_recovery(tmp_path):
    folder = tmp_path / "vault"
    v = Vault.create(folder, PASSWORD)
    with pytest.raises(VaultError, match="already open"):
        Vault.open(folder, PASSWORD)
    note_id = v.create_note("test note")
    v.save_note(note_id, "test note", "recoverable")
    v.lock()
    index = folder / "index.vlt"
    index.write_bytes(b"corrupted index")
    with pytest.raises(IntegrityError):
        Vault.open(folder, PASSWORD)
    chosen = Vault.recover_index(folder, PASSWORD)
    assert chosen.startswith("index-")
    reopened = Vault.open(folder, PASSWORD)
    assert reopened.note(note_id)["body"] == "recoverable"
    reopened.lock()


def test_no_accidental_plaintext_in_vault_or_recursive_folder_import(tmp_path):
    v = Vault.create(tmp_path / "outer" / "vault", PASSWORD)
    src = tmp_path / "file.txt"
    src.write_text("confidential")
    file_id = v.import_file(src)
    with pytest.raises(VaultError, match="plaintext"):
        v.export_file(file_id, v.root / "exported.txt")
    with pytest.raises(VaultError, match="plaintext"):
        v.export_readable_zip(v.root / "plain.zip")
    with pytest.raises(VaultError):
        v.import_folder(tmp_path / "outer")
    with pytest.raises(VaultError):
        v.import_folder(v.root)
    with pytest.raises(VaultError):
        v.import_file(v.root / "index.vlt")
    v.lock()


def test_batch_trash_restore_and_permanent_delete_mixed_types(tmp_path, monkeypatch):
    v = Vault.create(tmp_path / "vault", PASSWORD)
    notes = [v.create_note(f"note-{i}") for i in range(4)]
    source = tmp_path / "sample.bin"
    source.write_bytes(b"private video data" * 64)
    files = [v.import_file(source) for _ in range(2)]
    retained_note = notes[-1]
    targets = [("note", identity) for identity in notes[:3]] + [("file", identity) for identity in files]
    calls = []
    real_save = v._save

    def track_save(*args, **kwargs):
        calls.append(True)
        return real_save(*args, **kwargs)

    monkeypatch.setattr(v, "_save", track_save)
    before_logs = len(v.logs())
    # No partial mutation if a selected row is invalid.
    with pytest.raises(VaultError, match="no longer exists"):
        v.batch_move_to_trash(targets + [("note", "missing")])
    assert len(v.logs()) == before_logs
    assert len(v.list_notes()) == 4
    assert len(v.list_files()) == 2
    assert calls == []

    assert v.batch_move_to_trash(targets + targets[:1]) == 5
    assert len(calls) == 1
    assert len(v.list_notes()) == 1
    assert v.list_notes()[0]["id"] == retained_note
    assert len(v.list_notes(trashed=True)) == 3
    assert len(v.list_files(trashed=True)) == 2
    assert v.batch_move_to_trash(targets) == 0  # Already trashed.
    assert len(calls) == 1
    event_actions = [event["action"] for event in v.logs()]
    assert event_actions.count("note_trashed") == 3
    assert event_actions.count("file_trashed") == 2
    assert event_actions.count("batch_trashed") == 1

    # Only trashed entries may be destroyed, with full validation first.
    with pytest.raises(VaultError, match="before permanently deleting"):
        v.batch_permanently_delete(targets + [("note", retained_note)])
    assert len(v.list_files(trashed=True)) == 2
    assert len(calls) == 1

    assert v.batch_restore(targets) == 5
    assert len(calls) == 2
    assert len(v.list_notes()) == 4
    assert len(v.list_files()) == 2
    assert v.batch_restore(targets) == 0

    assert v.batch_move_to_trash(targets) == 5
    assert len(calls) == 3
    assert v.batch_permanently_delete(targets) == 5
    assert len(calls) == 4
    assert not v.list_files(trashed=True)
    assert not v.list_notes(trashed=True)
    assert len(v.list_notes()) == 1
    for identity in files:
        assert not (v.root / "blobs" / f"{identity}.bin").exists()
    actions = [e["action"] for e in v.logs()]
    assert actions.count("note_purged") == 3
    assert actions.count("file_purged") == 2
    assert "batch_purged" in actions
    v.lock()
    reopened = Vault.open(v.root, PASSWORD)
    assert len(reopened.list_notes()) == 1
    assert not reopened.list_files()
    assert not reopened.list_files(True)
    reopened.lock()
