# kayralrics vault — Fedora edition v1.1

A real, **fully local** notes and encrypted file-storage desktop application. The interface is in English, with a pure black (`#000000`) background and pure red (`#ff0000`) accents. Credit: **kayralrics.net**.

## Update from v1.0 (preserve all existing data)

The encrypted vault data stays in `~/.local/share/kayralrics-vault/vault/` by default, outside this program folder. **Do not delete that vault folder or replace it with the download.** Extract the v1.1 application package and run `./run.sh` there. It opens the same existing encrypted vault with the same password; there is no database migration. For additional safety, first create an encrypted backup from your existing app.

## Install on Fedora Linux

Open a terminal in this extracted folder:

```bash
chmod +x install-fedora.sh run.sh install-desktop-shortcut.sh
./install-fedora.sh
./run.sh
```

Optional desktop menu shortcut:

```bash
./install-desktop-shortcut.sh
```

If you prefer a Python virtual environment, install your local/system-provided Python dependencies there using `requirements.txt` and the `run.sh` launcher will use `.venv/bin/python` when available. Dependencies are required at installation, **not at runtime over the internet**.

## Interface previews

See `screenshots/multi-select-notes.png`, `screenshots/multi-select-trash.png`, `screenshots/notes.png`, `screenshots/logs.png` and `screenshots/settings.png` for screenshots captured from the running desktop application in a virtual Linux display.

## Included features

- **Password-protected vault.** On first launch create a master password (minimum 12 characters). Subsequent launches require it. There is no server, user account or password reset.
- **AES-256-GCM** encryption using independently random 96-bit nonces, with password-derived keys via **scrypt** (N=32768, r=8, p=1, 128-bit salt). AES-GCM authenticates all stored ciphertext. No plaintext password or key is stored on disk.
- **Notes:** create, rename, write, edit, manual save or 2.2-second debounced auto-save, search, move to trash, restore, permanently delete. Creation and last-edit timestamps. **v1.1 adds multi-select and batch move-to-trash.**
- **FILES:** multi-select files and move them all to Trash in a single action; import any regular file type, including videos, photos, source files, ZIPs and application/project assets. Import an entire folder while preserving relative subpaths. Files are **copied and encrypted into the application's own storage**, never linked back to Downloads. Symbolic links are ignored.
- **Image previews:** decrypt into memory for image display (Pillow, size cap 25 MiB). Videos and other files remain in encrypted storage until explicitly exported; there is no embedded video player in this release.
- **LOGS:** each item in a batch action receives its own encrypted history entry, plus a batch summary; encrypted, chronological activity records for vault access, navigation, note create/open/save/delete/restore, file import/open/export/delete/restore, backup and integrity actions, etc. No individual keystroke tracking; operations that fail before unlocking cannot be added to the encrypted log.
- **Trash:** select multiple mixed notes/files and restore or permanently delete them in one action. Important: permanent removal is not a guarantee of physical data erasure from SSDs, prior backups, or filesystem snapshots.
- **Encrypted full backups:** `.zip`, `.tar.gz`, `.tgz`, `.tar`. These contain ciphertext (`manifest.json`, `index.vlt`, and encrypted blobs) and are portable to another machine. Same vault password required. Includes trashed items and history. Extract safely through **Restore backup** into a new, empty folder. A backup restores the exact stored vault state at backup time.
- **Readable ZIP export:** deliberately unencrypted active notes, files and logs for interoperability, after an explicit warning. It excludes trashed items. There is no plaintext intermediate file.
- **Individual file export:** explicitly decrypt a chosen file into the destination you select. Exports are readable by other local software.
- **Integrity verification:** authenticate each encrypted file's AES-GCM tag and compare the plaintext size with the recorded size.
- **Automatic lock:** after 15 minutes without keyboard/mouse activity, unless an operation is running. An unsaved note requests confirmation.
- **Crash hygiene:** encrypted index writes are atomically replaced and previous encrypted index versions are retained (8 snapshots). On the unlock screen, **Recover damaged index** can restore the newest suitable prior encrypted index snapshot (some recent changes may be lost). Linux exclusive file locking prevents simultaneous writers. File import/export operates in chunks (1 MiB) with authenticated encryption; export writes to a temporary file and replaces the selected destination only after authentication. No internet code, APIs, telemetry, or cloud dependencies.

## Multi-selection (new in v1.1)

1. Open **NOTES**, **FILES**, or **TRASH** in the left navigation.
2. Ctrl-click rows to add/remove individual items, or Shift-click to select a range.
3. **SELECT ALL** picks all *visible* rows (including just filtered search results on Notes/Files); **CLEAR** removes the selection. Keyboard shortcuts when the list is focused: **Ctrl+A** selects all rows; **Esc** clears.
4. Select **TRASH SELECTED**, **RESTORE SELECTED**, or **DELETE PERMANENTLY** as appropriate. The selected item count is shown next to the controls. Permanent deletion requires confirmation and cannot be undone from the active vault.
5. Batch operations validate all requested item IDs before updating the encrypted index, write that index once, and log one event for each affected item plus a batch summary.

## Location and data layout

Default: `~/.local/share/kayralrics-vault/vault/`

```
vault/
  manifest.json           # plaintext format version, scrypt parameters, random salt ONLY
  index.vlt               # AES-GCM encrypted notes, filenames, metadata and event logs
  blobs/<random-id>.bin   # independently AES-GCM encrypted full file bodies
  snapshots/*.vlt         # previous encrypted index versions
```

All original filenames, note contents and event details are encrypted within `index.vlt`, not exposed as vault filenames. Sizes and number of files might still be inferred from the encrypted blob directory. Exported readable files or plaintext ZIPs are **not** encrypted.

## Security and limitations

1. No recovery if you forget the password. Store a long, unique password, and keep encrypted backups on a separate disk. A good password is more important than simply having AES-256.
2. Vault data are encrypted **at rest**, but are in application memory after unlocking. An attacker with an unlocked session, root access, malware, or physical access to RAM may access them. This is not full-disk encryption or a hardware-isolated key store.
3. The application logs meaningful user operations, **not every keystroke or external operating-system change**. The log is encrypted/authenticated but is **not tamper-proof against someone who knows the password**. Failed unlock attempts cannot be logged into the vault while the key is unavailable.
4. Moving objects to trash retains their encrypted bytes, and encrypted index snapshots retain older metadata. Old ciphertext in backups/drive snapshots may remain after permanent deletion.
5. The app uses Linux `flock` to prevent two application processes from opening the same vault for writing. Do not sync/copy the vault folder while it is actively being written; use the built-in encrypted backup feature instead.
6. Encrypted backup archives are protected against content disclosure by AES-GCM, but compression provides little benefit for already-encrypted blobs. For very large media, prefer ZIP or TAR over TAR.GZ for speed.
7. This edition does not provide embedded video playback, Markdown formatting, version history per note, a password change wizard, or GUI batch export of multiple selected files. They can be added in subsequent versions.
8. If the disk fills or hardware fails, data could still be lost. Keep **at least two independent backups** and periodically run integrity verification and a test restore.

## Run the automated storage tests

```bash
python3 -m pytest -q
```

To also smoke-test the real GUI without physically opening a window (requires Xvfb):

```bash
xvfb-run -a python3 -m pytest -q
```

All code is written for offline execution and is intentionally free of any network calls. Dependencies can be installed from standard Fedora distribution packages.
