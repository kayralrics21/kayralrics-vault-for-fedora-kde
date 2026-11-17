"""Smoke test the actual GUI on an X11 virtual display: xvfb-run -a python3 -m pytest -q."""
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from kayralrics_vault.gui import Application


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="Requires a display (use xvfb-run).")
def test_login_notes_autosave_and_navigation(tmp_path):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("No usable graphical display. Use xvfb-run to run GUI tests.")
    app = Application(root)
    try:
        app.vault_path = tmp_path / "ui-vault"
        app.welcome()
        app.password_var.set("some long local-only test password")
        app.confirm_var.set("some long local-only test password")
        app.authenticate()
        root.update()
        assert app.vault is not None
        app.new_note()
        identity = app.current_note_id
        app.title_var.set("Encrypted draft")
        app.editor.insert("1.0", "This should be autosaved")
        root.update()
        assert app.dirty
        # Tkafter fires during the event loop, simulate 2.2s idle.
        deadline = time.monotonic() + 3.5
        while time.monotonic() < deadline and app.dirty:
            root.update()
            time.sleep(0.05)
        assert not app.dirty
        assert app.vault.note(identity)["body"] == "This should be autosaved"
        for section in ("FILES", "TRASH", "LOGS", "SETTINGS", "NOTES"):
            app.navigate(section)
            root.update()
            assert app.page == section
        app.lock()
        assert app.vault is None
    finally:
        root.destroy()


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="Requires Xvfb or another graphical display")
def test_multi_select_notes_files_and_trash(tmp_path, monkeypatch):
    from kayralrics_vault import gui
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *args, **kwargs: True)
    root = tk.Tk()
    app = Application(root)
    try:
        app.vault_path = tmp_path / "vault"
        app.welcome()
        app.password_var.set("some long local-only test password")
        app.confirm_var.set("some long local-only test password")
        app.authenticate()
        for name in ("bulk-one", "bulk-two", "bulk-three", "keep-me"):
            app.vault.create_note(name)
        app.navigate("NOTES")
        root.update()
        assert app.note_list.cget("selectmode") == "extended"
        app.search_var.set("bulk-")
        root.update()
        app.select_all(app.note_list)
        root.update()
        assert len(app.note_list.curselection()) == 3
        assert app.selection_counter.cget("text").startswith("3 SELECTED")
        app.delete_note()
        root.update()
        assert {n["title"] for n in app.vault.list_notes()} == {"keep-me"}
        assert len(app.vault.list_notes(True)) == 3

        src = tmp_path / "source.bin"
        src.write_bytes(b"12345" * 100)
        ids = [app.vault.import_file(src) for _ in range(2)]
        app.navigate("FILES")
        root.update()
        app.select_all(app.file_list)
        root.update()
        assert len(app.file_list.curselection()) == 2
        app.delete_file()
        root.update()
        assert len(app.vault.list_files()) == 0
        assert len(app.vault.list_files(True)) == 2

        app.navigate("TRASH")
        root.update()
        assert app.trash_list.cget("selectmode") == "extended"
        app.select_all(app.trash_list)
        root.update()
        assert len(app.trash_list.curselection()) == 5
        app.restore_trash()
        root.update()
        assert len(app.vault.list_notes()) == 4
        assert len(app.vault.list_files()) == 2
        assert len(app.vault.list_files(True)) == 0
        for identity in ids:
            assert (app.vault.root / "blobs" / f"{identity}.bin").exists()

        app.navigate("NOTES")
        app.select_all(app.note_list)
        app.delete_note()
        app.navigate("FILES")
        app.select_all(app.file_list)
        app.delete_file()
        app.navigate("TRASH")
        app.select_all(app.trash_list)
        app.purge_trash()
        root.update()
        assert not app.vault.list_notes()
        assert not app.vault.list_files()
        assert not app.vault.list_notes(True)
        assert not app.vault.list_files(True)
        for identity in ids:
            assert not (app.vault.root / "blobs" / f"{identity}.bin").exists()
        assert any(e["action"] == "batch_purged" for e in app.vault.logs())
        app.lock()
    finally:
        root.destroy()
