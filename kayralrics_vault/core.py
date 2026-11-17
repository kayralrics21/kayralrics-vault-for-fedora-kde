"""Local-only encrypted storage engine. No network functions or services."""
from __future__ import annotations

import copy
import fcntl
import io
import json
import os
import re
import secrets
import shutil
import stat
import tarfile
import tempfile
import time
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
KDF_N = 2 ** 15
CHUNK = 1024 * 1024
INDEX_AAD = b"kayralrics-vault:index:v1"
INDEX_MAGIC = b"KVI1"
BLOB_MAGIC = b"KVB1"
Progress = Callable[[str], None]


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class IntegrityError(VaultError):
    pass


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def ensure_private_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)


def atomic_write(path: Path, data: bytes):
    ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _sync_directory(directory: Path):
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _exclusive_lock(root: Path) -> int:
    """Prevent concurrent writers to the same Fedora/Linux vault."""
    fd = os.open(root / ".session.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise VaultError("This vault is already open in another application window.") from exc
    except BaseException:
        os.close(fd)
        raise
    return fd


def _release_lock(fd: int | None):
    if fd is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _key(password: str, salt: bytes, n: int) -> bytes:
    if not isinstance(password, str) or not password:
        raise VaultError("A password is required.")
    if n < 2**14 or n > 2**18 or (n & (n - 1)):
        raise VaultError("Unsupported key derivation settings.")
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(password.encode("utf-8"))


def _index_encrypt(key: bytes, obj: dict) -> bytes:
    nonce = secrets.token_bytes(12)
    plain = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return INDEX_MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, INDEX_AAD)


def _index_decrypt(key: bytes, data: bytes) -> dict:
    if not data.startswith(INDEX_MAGIC) or len(data) < 4 + 12 + 16:
        raise IntegrityError("Vault index header is damaged.")
    try:
        obj = json.loads(AESGCM(key).decrypt(data[4:16], data[16:], INDEX_AAD))
    except InvalidTag as exc:
        raise WrongPassword("Incorrect password or damaged encrypted index.") from exc
    except (ValueError, UnicodeError) as exc:
        raise IntegrityError("Vault index is not valid JSON.") from exc
    if not isinstance(obj, dict) or obj.get("schema") != VERSION:
        raise IntegrityError("Unsupported or damaged vault index.")
    if not all(isinstance(obj.get(k), expected) for k, expected in (("notes", dict), ("files", dict), ("logs", list))):
        raise IntegrityError("Invalid vault index structure.")
    return obj


def _blob_aad(file_id: str) -> bytes:
    return b"kayralrics-vault:blob:v1:" + file_id.encode("ascii")


def _encrypt_blob(key: bytes, file_id: str, source: BinaryIO, dest: Path, progress: Progress | None = None) -> int:
    """Encrypt arbitrary-size files in constant memory; authenticate metadata ID as AAD."""
    nonce = secrets.token_bytes(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(_blob_aad(file_id))
    fd, tmp = tempfile.mkstemp(prefix=".partial-", dir=str(dest.parent))
    count = 0
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(BLOB_MAGIC + nonce)
            while True:
                block = source.read(CHUNK)
                if not block:
                    break
                count += len(block)
                out.write(enc.update(block))
                if progress:
                    progress(f"Encrypting {count / (1024 * 1024):,.1f} MiB")
            out.write(enc.finalize())
            out.write(enc.tag)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
        _sync_directory(dest.parent)
        return count
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _decrypt_blob(key: bytes, file_id: str, src: Path, out: BinaryIO, progress: Progress | None = None) -> int:
    total = src.stat().st_size
    if total < 4 + 12 + 16:
        raise IntegrityError(f"Encrypted file is truncated: {file_id}")
    with src.open("rb") as inp:
        head = inp.read(16)
        if head[:4] != BLOB_MAGIC:
            raise IntegrityError(f"Unrecognized encrypted file: {file_id}")
        inp.seek(-16, io.SEEK_END)
        tag = inp.read(16)
        dec = Cipher(algorithms.AES(key), modes.GCM(head[4:16], tag)).decryptor()
        dec.authenticate_additional_data(_blob_aad(file_id))
        inp.seek(16)
        remaining = total - 32
        count = 0
        while remaining:
            block = inp.read(min(CHUNK, remaining))
            if not block:
                raise IntegrityError(f"Missing bytes in encrypted file: {file_id}")
            remaining -= len(block)
            count += len(block)
            out.write(dec.update(block))
            if progress:
                progress(f"Decrypting {count / (1024 * 1024):,.1f} MiB")
        try:
            out.write(dec.finalize())
        except InvalidTag as exc:
            raise IntegrityError(f"Authentication failed for file: {file_id}") from exc
        return count


def _safe_archive_relative(value: str) -> str:
    """Reject absolute paths and path traversal for readable output/restoration."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise VaultError("Unsafe stored path.")
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")) or ":" in value.split("/")[0]:
        raise VaultError("Unsafe stored path.")
    return value


def _safe_filename(text: str) -> str:
    s = re.sub(r"[^\w. -]", "_", text.strip(), flags=re.UNICODE).strip(" .")
    return s[:90] or "untitled"


class Vault:
    """Encrypted local vault. Keep a single instance per opened vault."""

    def __init__(self, root: Path, key: bytes, document: dict, lock_fd: int):
        self.root = root
        self._key = key
        self.data = document
        self._mutex = threading.RLock()
        self._lock_fd = lock_fd

    @property
    def locked(self) -> bool:
        return self._key is None

    def _unlocked(self):
        if self.locked:
            raise VaultError("The vault is locked.")

    @classmethod
    def create(cls, root: Path | str, password: str) -> "Vault":
        path = Path(root).expanduser().resolve()
        if len(password) < 12:
            raise VaultError("Use a password of at least 12 characters.")
        if path.exists() and any(path.iterdir()):
            raise VaultError("Choose an empty folder for a new vault.")
        ensure_private_dir(path)
        ensure_private_dir(path / "blobs")
        ensure_private_dir(path / "snapshots")
        lock_fd = _exclusive_lock(path)
        try:
            salt = secrets.token_bytes(16)
            manifest = {"format": VERSION, "kdf": "scrypt", "n": KDF_N, "r": 8, "p": 1, "salt": salt.hex()}
            key = _key(password, salt, KDF_N)
            doc = {"schema": VERSION, "created_at": now(), "notes": {}, "files": {}, "logs": []}
            obj = cls(path, key, doc, lock_fd)
            obj._event("vault_created", "vault", "", "Encrypted vault created")
            atomic_write(path / "manifest.json", json.dumps(manifest, sort_keys=True).encode())
            obj._save(snapshot=False)
            return obj
        except BaseException:
            _release_lock(lock_fd)
            raise

    @classmethod
    def open(cls, root: Path | str, password: str) -> "Vault":
        path = Path(root).expanduser().resolve()
        if not path.is_dir():
            raise VaultError("The vault folder does not exist.")
        lock_fd = _exclusive_lock(path)
        try:
            key = cls._read_key(path, password)
            try:
                index_bytes = (path / "index.vlt").read_bytes()
            except OSError as exc:
                raise VaultError("Cannot read the encrypted vault index.") from exc
            doc = _index_decrypt(key, index_bytes)
            obj = cls(path, key, doc, lock_fd)
            obj._event("vault_unlocked", "vault", "", "Vault unlocked locally")
            obj._save()
            return obj
        except BaseException:
            _release_lock(lock_fd)
            raise

    @staticmethod
    def _read_key(path: Path, password: str) -> bytes:
        try:
            info = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
            if info.get("format") != VERSION or info.get("kdf") != "scrypt" or info.get("r") != 8 or info.get("p") != 1:
                raise VaultError("Unsupported vault format.")
            salt = bytes.fromhex(info["salt"])
            if len(salt) != 16:
                raise VaultError("Invalid vault salt.")
            n = int(info["n"])
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise VaultError("Cannot read the vault manifest.") from exc
        return _key(password, salt, n)

    @classmethod
    def recover_index(cls, root: Path | str, password: str) -> str:
        """Explicitly restore the newest decryptable encrypted index snapshot."""
        path = Path(root).expanduser().resolve()
        if not path.is_dir():
            raise VaultError("Vault folder does not exist.")
        lock_fd = _exclusive_lock(path)
        try:
            key = cls._read_key(path, password)
            candidates = sorted((path / "snapshots").glob("index-*.vlt"), reverse=True)
            if not candidates:
                raise VaultError("No prior encrypted index snapshots are available.")
            for candidate in candidates:
                data = candidate.read_bytes()
                try:
                    doc = _index_decrypt(key, data)
                except (WrongPassword, IntegrityError):
                    continue
                # Do not resurrect references to missing encrypted file bodies.
                if any(not (path / "blobs" / (k + ".bin")).is_file() for k in doc["files"]):
                    continue
                atomic_write(path / "index.vlt", data)
                return candidate.name
            raise VaultError("No usable snapshot with all its encrypted files was found. Check your password.")
        finally:
            _release_lock(lock_fd)

    def lock(self):
        with self._mutex:
            if self.locked:
                return
            self._event("vault_locked", "vault", "", "Vault locked")
            self._save()
            self._key = None
            self.data = {"notes": {}, "files": {}, "logs": []}
            _release_lock(self._lock_fd)
            self._lock_fd = None

    def _event(self, action: str, kind: str, identity: str, detail: str = ""):
        self.data["logs"].append({
            "id": uuid.uuid4().hex, "at": now(), "action": action,
            "kind": kind, "item_id": identity, "detail": detail[:300],
        })

    def log(self, action: str, kind: str = "ui", identity: str = "", detail: str = ""):
        with self._mutex:
            self._unlocked()
            self._event(action, kind, identity, detail)
            self._save()

    def _save(self, snapshot: bool = True):
        self._unlocked()
        path = self.root / "index.vlt"
        if snapshot and path.exists():
            backups = self.root / "snapshots"
            ensure_private_dir(backups)
            stamp = f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}"
            # Already encrypted; snapshots retain previous indexes, not plaintext.
            atomic_write(backups / f"index-{stamp}.vlt", path.read_bytes())
            names = sorted(backups.glob("index-*.vlt"))
            for old in names[:-8]:
                old.unlink()
        atomic_write(path, _index_encrypt(self._key, self.data))

    def list_notes(self, trashed: bool = False) -> list[dict]:
        with self._mutex:
            self._unlocked()
            return sorted((copy.deepcopy(v) for v in self.data["notes"].values() if bool(v["trashed_at"]) == trashed),
                          key=lambda n: n["updated_at"], reverse=True)

    def note(self, identity: str) -> dict:
        with self._mutex:
            self._unlocked()
            try:
                return copy.deepcopy(self.data["notes"][identity])
            except KeyError as exc:
                raise VaultError("Note not found.") from exc

    def create_note(self, title: str = "Untitled note") -> str:
        with self._mutex:
            self._unlocked()
            identity = uuid.uuid4().hex
            stamp = now()
            self.data["notes"][identity] = {"id": identity, "title": title[:220] or "Untitled note",
                "body": "", "created_at": stamp, "updated_at": stamp, "trashed_at": None}
            self._event("note_created", "note", identity, title)
            self._save()
            return identity

    def save_note(self, identity: str, title: str, body: str):
        with self._mutex:
            self._unlocked()
            item = self.data["notes"].get(identity)
            if item is None or item["trashed_at"]:
                raise VaultError("This note cannot be edited.")
            if len(title) > 220:
                raise VaultError("A title cannot exceed 220 characters.")
            title = title.strip() or "Untitled note"
            if item["title"] == title and item["body"] == body:
                return False
            item.update(title=title, body=body, updated_at=now())
            self._event("note_updated", "note", identity, title)
            self._save()
            return True

    def list_files(self, trashed: bool = False) -> list[dict]:
        with self._mutex:
            self._unlocked()
            return sorted((copy.deepcopy(v) for v in self.data["files"].values() if bool(v["trashed_at"]) == trashed),
                          key=lambda f: f["added_at"], reverse=True)

    def file(self, identity: str) -> dict:
        with self._mutex:
            self._unlocked()
            try:
                return copy.deepcopy(self.data["files"][identity])
            except KeyError as exc:
                raise VaultError("File not found.") from exc

    def import_file(self, source: Path | str, relative_path: str | None = None, progress: Progress | None = None) -> str:
        with self._mutex:
            self._unlocked()
            src = Path(source).expanduser()
            if self.root == src.resolve() or self.root in src.resolve().parents:
                raise VaultError("Do not import the active vault into itself.")
            if not src.is_file() or src.is_symlink():
                raise VaultError("Only regular files may be imported; symlinks are skipped.")
            rel = _safe_archive_relative(relative_path or src.name)
            identity = uuid.uuid4().hex
            dest = self.root / "blobs" / (identity + ".bin")
            log_count = len(self.data["logs"])
            try:
                with src.open("rb") as inp:
                    size = _encrypt_blob(self._key, identity, inp, dest, progress)
                record = {"id": identity, "name": src.name, "path": rel, "size": size,
                          "added_at": now(), "trashed_at": None}
                self.data["files"][identity] = record
                self._event("file_imported", "file", identity, rel)
                self._save()
                return identity
            except BaseException:
                self.data["files"].pop(identity, None)
                del self.data["logs"][log_count:]
                dest.unlink(missing_ok=True)
                raise

    def import_folder(self, folder: Path | str, progress: Progress | None = None) -> tuple[int, list[str]]:
        root = Path(folder).expanduser()
        resolved = root.resolve()
        if resolved == self.root or resolved in self.root.parents or self.root in resolved.parents:
            raise VaultError("Do not import the active vault folder or a folder containing it.")
        if not root.is_dir() or root.is_symlink():
            raise VaultError("Choose an ordinary folder.")
        count, errors = 0, []
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
            for name in sorted(files):
                source = Path(current) / name
                if source.is_symlink() or not source.is_file():
                    continue
                rel = (Path(root.name) / source.relative_to(root)).as_posix()
                if progress:
                    progress(f"Importing {rel}")
                try:
                    self.import_file(source, rel, progress)
                    count += 1
                except (OSError, VaultError) as exc:
                    errors.append(f"{rel}: {exc}")
        if count:
            self.log("folder_imported", "folder", "", f"{root.name}: {count} files; {len(errors)} errors")
        return count, errors

    def _encrypted_file(self, identity: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", identity):
            raise VaultError("Invalid file identifier.")
        return self.root / "blobs" / (identity + ".bin")

    def file_bytes(self, identity: str, max_bytes: int = 25 * 1024 * 1024) -> bytes:
        with self._mutex:
            self._unlocked()
            item = self.file(identity)
            if item["size"] > max_bytes:
                raise VaultError("This file is too large for an in-memory preview.")
            buf = io.BytesIO()
            result = _decrypt_blob(self._key, identity, self._encrypted_file(identity), buf)
            if result != item["size"]:
                raise IntegrityError("The decrypted file has an unexpected size.")
            return buf.getvalue()

    def export_file(self, identity: str, destination: Path | str, progress: Progress | None = None):
        with self._mutex:
            self._unlocked()
            item = self.file(identity)
            target = Path(destination).expanduser()
            if target.resolve() == self.root or self.root in target.resolve().parents:
                raise VaultError("Refusing to export readable plaintext into the encrypted vault directory.")
            if not target.parent.is_dir():
                raise VaultError("Export folder does not exist.")
            fd, temp = tempfile.mkstemp(prefix=".export-", dir=str(target.parent))
            try:
                with os.fdopen(fd, "wb") as out:
                    count = _decrypt_blob(self._key, identity, self._encrypted_file(identity), out, progress)
                    if count != item["size"]:
                        raise IntegrityError("Export size does not match recorded size.")
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temp, target)
                self._event("file_exported_plaintext", "file", identity, item["path"])
                self._save()
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)

    def _batch_change(self, items: list[tuple[str, str]], operation: str) -> int:
        """Validate selection first, then commit one encrypted index with itemized logs."""
        with self._mutex:
            self._unlocked()
            if operation not in ("trash", "restore", "purge"):
                raise VaultError("Unsupported batch action.")
            unique = list(dict.fromkeys(items))
            targets = []
            for kind, identity in unique:
                if kind not in ("note", "file"):
                    raise VaultError("Unsupported trash item type.")
                collection = self.data["notes" if kind == "note" else "files"]
                obj = collection.get(identity)
                if obj is None:
                    raise VaultError("Selected item no longer exists. Refresh and try again.")
                if operation == "purge" and not obj["trashed_at"]:
                    raise VaultError("Move the item to trash before permanently deleting it.")
                if operation == "trash" and obj["trashed_at"]:
                    continue
                if operation == "restore" and not obj["trashed_at"]:
                    continue
                targets.append((kind, identity, collection, obj))

            if not targets:
                return 0
            timestamp = now()
            old_logs = len(self.data["logs"])
            # Keep in-memory data consistent if the encrypted index write fails.
            old_values = [(collection, identity, copy.deepcopy(obj))
                          for _, identity, collection, obj in targets]
            verb = {"trash": "trashed", "restore": "restored", "purge": "purged"}[operation]
            try:
                for kind, identity, collection, obj in targets:
                    detail = obj.get("title", obj.get("path", ""))
                    if operation == "trash":
                        obj["trashed_at"] = timestamp
                    elif operation == "restore":
                        obj["trashed_at"] = None
                    else:
                        del collection[identity]
                    self._event(f"{kind}_{verb}", kind, identity, detail)
                if len(targets) > 1:
                    self._event(f"batch_{verb}", "vault", "", f"{len(targets)} items")
                self._save()
            except Exception:
                for collection, identity, obj in old_values:
                    collection[identity] = obj
                del self.data["logs"][old_logs:]
                raise

            # Ciphertext is deleted only after the encrypted index no longer
            # references it. Older backups/snapshots may still hold ciphertext.
            if operation == "purge":
                for kind, identity, _, _ in targets:
                    if kind == "file":
                        self._encrypted_file(identity).unlink(missing_ok=True)
            return len(targets)

    def batch_move_to_trash(self, items: list[tuple[str, str]]) -> int:
        return self._batch_change(items, "trash")

    def batch_restore(self, items: list[tuple[str, str]]) -> int:
        return self._batch_change(items, "restore")

    def batch_permanently_delete(self, items: list[tuple[str, str]]) -> int:
        return self._batch_change(items, "purge")

    def move_to_trash(self, kind: str, identity: str):
        self.batch_move_to_trash([(kind, identity)])

    def restore(self, kind: str, identity: str):
        self.batch_restore([(kind, identity)])

    def permanently_delete(self, kind: str, identity: str):
        self.batch_permanently_delete([(kind, identity)])

    def logs(self, query: str = "") -> list[dict]:
        with self._mutex:
            self._unlocked()
            rows = reversed(self.data["logs"])
            if query:
                q = query.casefold()
                return [copy.deepcopy(v) for v in rows if q in json.dumps(v, ensure_ascii=False).casefold()]
            return [copy.deepcopy(v) for v in rows]

    def stats(self) -> dict:
        with self._mutex:
            self._unlocked()
            return {"notes": sum(1 for n in self.data["notes"].values() if not n["trashed_at"]),
                    "files": sum(1 for f in self.data["files"].values() if not f["trashed_at"]),
                    "bytes": sum(f["size"] for f in self.data["files"].values()),
                    "trash": sum(bool(n["trashed_at"]) for n in self.data["notes"].values()) +
                             sum(bool(f["trashed_at"]) for f in self.data["files"].values()),
                    "logs": len(self.data["logs"])}

    def verify(self, progress: Progress | None = None) -> tuple[int, list[str]]:
        """Authenticated GCM tag check for all encrypted files, without writing plaintext."""
        class Sink:
            def write(self, data):
                return len(data)
        with self._mutex:
            self._unlocked()
            issues = []
            for i, (identity, item) in enumerate(self.data["files"].items(), 1):
                if progress:
                    progress(f"Verifying file {i}/{len(self.data['files'])}: {item['path']}")
                try:
                    actual = _decrypt_blob(self._key, identity, self._encrypted_file(identity), Sink())
                    if actual != item["size"]:
                        raise IntegrityError("Recorded byte size does not match.")
                except (OSError, VaultError) as exc:
                    issues.append(f"{item['path']}: {exc}")
            self._event("integrity_verified", "vault", "", f"Checked {len(self.data['files'])} files; {len(issues)} issues")
            self._save()
            return len(self.data["files"]), issues

    def export_encrypted_backup(self, destination: Path | str, progress: Progress | None = None):
        """Portable backup containing ciphertext only (including names/notes/logs)."""
        with self._mutex:
            self._unlocked()
            target = Path(destination).expanduser()
            if target.resolve() == self.root or self.root in target.resolve().parents:
                raise VaultError("Write backups outside the active vault folder.")
            fmt = _archive_format(target)
            ids = list(self.data["files"].keys())
            sources = [("manifest.json", self.root / "manifest.json"), ("index.vlt", self.root / "index.vlt")]
            sources += [(f"blobs/{i}.bin", self._encrypted_file(i)) for i in ids]
            for _, file in sources:
                if not file.is_file():
                    raise VaultError(f"Missing encrypted vault component: {file.name}")
            temp = _temp_target(target)
            try:
                if fmt == "zip":
                    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                        for i, (name, file) in enumerate(sources, 1):
                            if progress:
                                progress(f"Backing up {i}/{len(sources)}: {name}")
                            archive.write(file, name)
                else:
                    with tarfile.open(temp, "w:gz" if fmt == "tar.gz" else "w") as archive:
                        for i, (name, file) in enumerate(sources, 1):
                            if progress:
                                progress(f"Backing up {i}/{len(sources)}: {name}")
                            archive.add(file, arcname=name, recursive=False)
                os.replace(temp, target)
                self._event("encrypted_backup_exported", "vault", "", f"{fmt} backup written")
                self._save()
            finally:
                Path(temp).unlink(missing_ok=True)

    def export_readable_zip(self, destination: Path | str, progress: Progress | None = None):
        """Explicitly requested PLAINTEXT ZIP. No unencrypted intermediate file is created."""
        with self._mutex:
            self._unlocked()
            target = Path(destination).expanduser()
            if target.resolve() == self.root or self.root in target.resolve().parents:
                raise VaultError("Refusing to put a plaintext ZIP inside the encrypted vault directory.")
            if target.suffix.lower() != ".zip":
                raise VaultError("Readable archives must use .zip.")
            temp = _temp_target(target)
            try:
                with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                    for i, item in enumerate(self.list_notes(), 1):
                        name = f"notes/{_safe_filename(item['title'])}-{item['id'][:8]}.txt"
                        archive.writestr(name, item["body"].encode("utf-8"))
                    seen = set()
                    for i, item in enumerate(self.list_files(), 1):
                        name = "files/" + _safe_archive_relative(item["path"])
                        if name in seen:
                            name = "files/duplicates/" + item["id"][:8] + "/" + item["name"]
                        name = _safe_archive_relative(name)
                        seen.add(name)
                        if progress:
                            progress(f"Exporting file {i}: {item['path']}")
                        with archive.open(name, "w", force_zip64=True) as out:
                            count = _decrypt_blob(self._key, item["id"], self._encrypted_file(item["id"]), out)
                            if count != item["size"]:
                                raise IntegrityError("Size mismatch while exporting readable backup.")
                    archive.writestr("logs.json", json.dumps(self.logs(), ensure_ascii=False, indent=2).encode("utf-8"))
                    summary = {"created_at": now(), "notes": len(self.list_notes()), "files": len(self.list_files()),
                               "warning": "This archive is NOT encrypted and does not include trashed items."}
                    archive.writestr("README.json", json.dumps(summary, indent=2))
                os.replace(temp, target)
                self._event("readable_backup_exported", "vault", "", "UNENCRYPTED ZIP exported by user")
                self._save()
            finally:
                Path(temp).unlink(missing_ok=True)


def _archive_format(path: Path) -> str:
    p = path.name.lower()
    if p.endswith(".tar.gz") or p.endswith(".tgz"):
        return "tar.gz"
    if p.endswith(".zip"):
        return "zip"
    if p.endswith(".tar"):
        return "tar"
    raise VaultError("Use .zip, .tar.gz, .tgz or .tar for encrypted backups.")


def _temp_target(target: Path) -> Path:
    if not target.parent.is_dir():
        raise VaultError("Export folder does not exist.")
    fd, path = tempfile.mkstemp(prefix=".vault-backup-", dir=target.parent)
    os.close(fd)
    return Path(path)


def restore_encrypted_backup(archive_path: Path | str, destination: Path | str, progress: Progress | None = None):
    """Restore ONLY a known, safe encrypted-backup layout into a fresh vault folder.

    No arbitrary paths or symlinks from untrusted archives are extracted.
    Password is NOT required until the restored vault is opened.
    """
    src = Path(archive_path).expanduser()
    root = Path(destination).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise VaultError("Restore requires a new, empty destination folder.")
    if not src.is_file():
        raise VaultError("Backup archive was not found.")
    fmt = _archive_format(src)
    ensure_private_dir(root)
    ensure_private_dir(root / "blobs")
    ensure_private_dir(root / "snapshots")
    extracted = set()

    def permitted(name: str) -> bool:
        return name in ("manifest.json", "index.vlt") or bool(re.fullmatch(r"blobs/[0-9a-f]{32}\.bin", name))

    def copy_member(name: str, fileobj: BinaryIO):
        if not permitted(name) or name in extracted:
            raise VaultError(f"Unsafe or duplicate backup entry: {name[:120]}")
        dest = root / name
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(fileobj, out, CHUNK)
            out.flush()
            os.fsync(out.fileno())
        extracted.add(name)
        if progress:
            progress(f"Restored {len(extracted)} encrypted components")

    try:
        if fmt == "zip":
            with zipfile.ZipFile(src) as z:
                for entry in z.infolist():
                    if entry.is_dir() or ((entry.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
                        raise VaultError("Backup includes an unsupported link/directory entry.")
                    with z.open(entry) as reader:
                        copy_member(entry.filename, reader)
        else:
            with tarfile.open(src, "r:gz" if fmt == "tar.gz" else "r:") as t:
                for entry in t:
                    if not entry.isfile():
                        raise VaultError("Backup includes a non-file entry.")
                    reader = t.extractfile(entry)
                    if reader is None:
                        raise VaultError("Cannot read a backup entry.")
                    with reader:
                        copy_member(entry.name, reader)
        if not {"manifest.json", "index.vlt"}.issubset(extracted):
            raise VaultError("Backup is incomplete (manifest or index missing).")
        info = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if info.get("format") != VERSION or info.get("kdf") != "scrypt":
            raise VaultError("Restored manifest is unsupported.")
    except BaseException:
        # This folder was empty before extraction. Remove failed partial restoration.
        shutil.rmtree(root, ignore_errors=True)
        raise


DEFAULT_VAULT = Path.home() / ".local" / "share" / "kayralrics-vault" / "vault"
