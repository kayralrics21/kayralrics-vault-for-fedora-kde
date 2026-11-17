"""Fedora-friendly Tk desktop interface; all functionality stays on this computer."""
from __future__ import annotations

import io
import json
import mimetypes
import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .core import DEFAULT_VAULT, Vault, VaultError, WrongPassword, restore_encrypted_backup

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None

BLACK = "#000000"
RED = "#ff0000"
WHITE = "#ffffff"
MUTED = "#989898"
DIM = "#555555"
FONT = "DejaVu Sans"
MONO = "DejaVu Sans Mono"


def button(parent, text, command, selected=False, compact=False, width=None):
    widget = tk.Button(
        parent, text=text, command=command, font=(FONT, 10, "bold"),
        bg=RED if selected else BLACK, fg=BLACK if selected else RED,
        activebackground=RED, activeforeground=BLACK,
        highlightthickness=0, relief="solid", bd=1,
        cursor="hand2", padx=9 if compact else 17, pady=5 if compact else 10,
        width=width,
    )
    widget.bind("<Enter>", lambda e: widget.configure(bg=RED, fg=BLACK))
    widget.bind("<Leave>", lambda e: widget.configure(
        bg=RED if getattr(widget, "selected", False) else BLACK,
        fg=BLACK if getattr(widget, "selected", False) else RED))
    widget.selected = selected
    return widget


def line(parent, vertical=False):
    f = tk.Frame(parent, bg=RED, width=1 if vertical else None, height=1 if not vertical else None)
    return f


def label(parent, value, size=11, color=WHITE, bold=False, **kw):
    return tk.Label(parent, text=value, bg=BLACK, fg=color, font=(FONT, size, "bold" if bold else "normal"), **kw)


def entry(parent, value=None, password=False, **kwargs):
    widget = tk.Entry(parent, textvariable=value, show="•" if password else "", font=(FONT, 11),
                      bg=BLACK, fg=WHITE, insertbackground=RED, selectbackground=RED,
                      selectforeground=BLACK, highlightbackground=RED, highlightcolor=RED,
                      highlightthickness=1, relief="flat", bd=0, **kwargs)
    return widget


def listbox(parent, selectmode="browse"):
    return tk.Listbox(parent, bg=BLACK, fg=WHITE, selectbackground=RED, selectforeground=BLACK,
                      highlightbackground=RED, highlightcolor=RED, highlightthickness=1,
                      relief="flat", borderwidth=0, font=(FONT, 10),
                      activestyle="none", exportselection=False, selectmode=selectmode)


def textwidget(parent, **kwargs):
    return tk.Text(parent, bg=BLACK, fg=WHITE, insertbackground=RED, selectbackground=RED,
                   selectforeground=BLACK, highlightbackground=RED, highlightcolor=RED,
                   highlightthickness=1, relief="flat", borderwidth=0,
                   font=(MONO, 11), padx=15, pady=15, wrap="word", undo=True,
                   **kwargs)


def size_text(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    num = float(n)
    for unit in units:
        if num < 1024 or unit == "TiB":
            return f"{num:,.1f} {unit}"
        num /= 1024
    return str(n)


class Application:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("kayralrics vault — Fedora")
        self.root.geometry("1260x810")
        self.root.minsize(950, 620)
        self.root.configure(bg=BLACK)
        self.root.option_add("*Dialog.msg.font", (FONT, 10))
        self.vault_path = DEFAULT_VAULT
        self.vault: Vault | None = None
        self.page = "NOTES"
        self.current_note_id: str | None = None
        self.current_file_id: str | None = None
        self.dirty = False
        self.loading_editor = False
        self.search_var = tk.StringVar()
        self._list_ids = []
        self._trash_ids = []
        self._log_rows = []
        self._busy = False
        self._last_activity = time.monotonic()
        self._image = None
        self._autosave_handle = None
        self._last_saved_title = ""
        self._last_saved_body = ""
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.bind_all("<Control-s>", self.shortcut_save)
        self.root.bind_all("<Control-n>", self.shortcut_new)
        self.root.bind_all("<Control-l>", self.shortcut_lock)
        self.root.bind_all("<Control-f>", self.shortcut_find)
        self.root.bind_all("<F5>", self.shortcut_refresh)
        for event in ("<Key>", "<Button>", "<Motion>"):
            self.root.bind_all(event, self.activity, add="+")
        self.root.after(30_000, self.auto_lock_check)
        self.welcome()

    def activity(self, _event=None):
        self._last_activity = time.monotonic()

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def welcome(self):
        self.clear()
        self.vault = None
        self.current_note_id = None
        self.current_file_id = None
        self.dirty = False
        wrapper = tk.Frame(self.root, bg=BLACK)
        wrapper.pack(expand=True, fill="both")
        shell = tk.Frame(wrapper, bg=BLACK, width=540, highlightbackground=RED, highlightthickness=1)
        shell.place(relx=0.5, rely=0.49, anchor="center", width=550, height=560)
        box = tk.Frame(shell, bg=BLACK, padx=35, pady=30)
        box.pack(fill="both", expand=True)
        label(box, "KAYRALRICS", 24, WHITE, bold=True, anchor="w").pack(fill="x")
        label(box, "VAULT  /  ENCRYPTED OFFLINE STORAGE", 11, RED, bold=True, anchor="w").pack(fill="x", pady=(2, 24))
        line(box).pack(fill="x", pady=(0, 22))
        exists = (self.vault_path / "index.vlt").exists()
        mode = "UNLOCK YOUR VAULT" if exists else "CREATE YOUR VAULT"
        label(box, mode, 13, WHITE, bold=True, anchor="w").pack(fill="x", pady=(0, 8))
        self.path_label = label(box, str(self.vault_path), 9, MUTED, anchor="w", wraplength=475, justify="left")
        self.path_label.pack(fill="x", pady=(0, 13))
        self.password_var = tk.StringVar()
        password_field = entry(box, self.password_var, password=True)
        password_field.pack(fill="x", ipady=12, pady=(0, 12))
        password_field.focus_set()
        self.confirm_var = tk.StringVar()
        if not exists:
            label(box, "CONFIRM PASSWORD", 9, MUTED, anchor="w").pack(fill="x", pady=(0, 6))
            entry(box, self.confirm_var, password=True).pack(fill="x", ipady=12, pady=(0, 14))
        actions = tk.Frame(box, bg=BLACK)
        actions.pack(fill="x", pady=(5, 7))
        button(actions, "UNLOCK" if exists else "CREATE VAULT", self.authenticate, selected=True).pack(side="left", fill="x", expand=True)
        button(actions, "CHOOSE FOLDER", self.choose_vault_folder, compact=True).pack(side="left", padx=(10, 0))
        button(box, "RESTORE ENCRYPTED BACKUP", self.restore_backup_dialog, compact=True).pack(anchor="w", pady=(9, 0))
        if exists:
            button(box, "RECOVER DAMAGED INDEX", self.recover_index_dialog, compact=True).pack(anchor="w", pady=(8, 0))
        label(box, "No accounts  •  No servers  •  Nothing leaves this device", 9, MUTED, anchor="w").pack(fill="x", pady=(20, 0))
        label(wrapper, "kayralrics.net", 10, RED).place(relx=0.5, rely=0.95, anchor="center")
        password_field.bind("<Return>", lambda e: self.authenticate())

    def choose_vault_folder(self):
        path = filedialog.askdirectory(title="Choose existing vault or empty folder", initialdir=str(self.vault_path.parent))
        if path:
            self.vault_path = Path(path).expanduser().resolve()
            self.welcome()

    def authenticate(self):
        password = self.password_var.get()
        try:
            if (self.vault_path / "index.vlt").exists():
                vault = Vault.open(self.vault_path, password)
            else:
                if (self.vault_path / "manifest.json").exists():
                    raise VaultError("An incomplete vault exists here. Do not overwrite it.")
                if password != self.confirm_var.get():
                    raise VaultError("Passwords do not match.")
                vault = Vault.create(self.vault_path, password)
        except (VaultError, OSError) as exc:
            messagebox.showerror("Vault access failed", str(exc), parent=self.root)
            self.password_var.set("")
            return
        self.password_var.set("")
        self.confirm_var.set("")
        self.vault = vault
        self.page = "NOTES"
        self._last_activity = time.monotonic()
        self.shell()
        self.navigate("NOTES", initial=True)

    def recover_index_dialog(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Password needed", "Enter the original password above to recover the index.")
            return
        if not messagebox.askyesno("Recover encrypted index", "Restore an earlier encrypted index snapshot?\n\nRecent note changes or metadata may be lost. Keep an external backup when possible.", icon="warning"):
            return
        try:
            snapshot = Vault.recover_index(self.vault_path, password)
            self.authenticate()
            if self.vault:
                self.vault.log("index_recovered", "vault", "", snapshot)
            messagebox.showinfo("Recovery complete", "Restored encrypted index from: " + snapshot)
        except (VaultError, OSError) as exc:
            messagebox.showerror("Recovery failed", str(exc))

    def restore_backup_dialog(self):
        backup = filedialog.askopenfilename(title="Encrypted backup", filetypes=[
            ("Encrypted backups", "*.zip *.tar.gz *.tgz *.tar"), ("All files", "*")])
        if not backup:
            return
        destination = filedialog.askdirectory(title="Select a NEW empty folder for the restored vault")
        if not destination:
            return
        dest = Path(destination).resolve()
        if dest == self.vault_path.resolve():
            messagebox.showerror("Restore", "Do not restore on top of your current vault.")
            return
        if not messagebox.askyesno("Restore encrypted backup", "Restore into this empty folder?\n\n" + str(dest)):
            return
        def after(_):
            if self.vault and not self.vault.locked:
                self.vault.log("backup_restored_to_folder", "vault", "", "Encrypted backup restored into separate folder")
                self.vault.lock()
            self.vault_path = dest
            self.welcome()
            messagebox.showinfo("Backup restored", "Encrypted backup restored. Unlock it with its ORIGINAL password.")
        self.job("RESTORING ENCRYPTED BACKUP", lambda update: restore_encrypted_backup(backup, dest, update), after)

    def shell(self):
        self.clear()
        outer = tk.Frame(self.root, bg=BLACK)
        outer.pack(fill="both", expand=True)
        self.sidebar = tk.Frame(outer, bg=BLACK, width=210, padx=16, pady=22)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        label(self.sidebar, "KAYRALRICS", 16, WHITE, bold=True, anchor="w").pack(fill="x")
        label(self.sidebar, "VAULT", 13, RED, bold=True, anchor="w").pack(fill="x", pady=(0, 25))
        line(self.sidebar).pack(fill="x", pady=(0, 20))
        self.nav_buttons = {}
        for name, icon in (("NOTES", "01"), ("FILES", "02"), ("TRASH", "03"), ("LOGS", "04"), ("SETTINGS", "05")):
            b = button(self.sidebar, f"{icon}   {name}", lambda n=name: self.navigate(n))
            b.configure(anchor="w")
            b.pack(fill="x", pady=(0, 11))
            self.nav_buttons[name] = b
        tk.Frame(self.sidebar, bg=BLACK).pack(fill="both", expand=True)
        line(self.sidebar).pack(fill="x", pady=(0, 16))
        label(self.sidebar, "AES-256-GCM", 10, RED, bold=True, anchor="w").pack(fill="x")
        label(self.sidebar, "LOCAL • ENCRYPTED", 9, MUTED, anchor="w").pack(fill="x", pady=(2, 15))
        button(self.sidebar, "LOCK  [Ctrl+L]", self.lock, compact=True).pack(fill="x")
        label(self.sidebar, "kayralrics.net", 10, RED).pack(pady=(22, 0))
        line(outer, vertical=True).pack(side="left", fill="y")
        self.main = tk.Frame(outer, bg=BLACK)
        self.main.pack(side="left", fill="both", expand=True)
        self.heading = tk.Frame(self.main, bg=BLACK, padx=26, pady=20)
        self.heading.pack(fill="x")
        self.heading_title = label(self.heading, "NOTES", 20, WHITE, bold=True, anchor="w")
        self.heading_title.pack(side="left")
        self.heading_subtitle = label(self.heading, "", 10, MUTED)
        self.heading_subtitle.pack(side="right")
        line(self.main).pack(fill="x")
        self.content = tk.Frame(self.main, bg=BLACK)
        self.content.pack(fill="both", expand=True, padx=25, pady=23)
        line(self.main).pack(fill="x")
        self.status = label(self.main, "", 9, MUTED, anchor="w")
        self.status.pack(fill="x", padx=25, pady=12)

    def status_update(self, description="READY"):
        if self.vault and not self.vault.locked:
            s = self.vault.stats()
            self.status.configure(text=f"{description}    •    {s['notes']} NOTES    •    {s['files']} FILES    •    {s['logs']} EVENTS    •    OFFLINE")

    def nav_selected(self):
        for page, b in self.nav_buttons.items():
            chosen = page == self.page
            b.selected = chosen
            b.configure(bg=RED if chosen else BLACK, fg=BLACK if chosen else RED)

    def confirm_note_change(self) -> bool:
        if not self.dirty or not self.vault or self.page != "NOTES":
            return True
        response = messagebox.askyesnocancel("Unsaved note", "Save your changes before continuing?", parent=self.root)
        if response is None:
            return False
        if response:
            return self.save_note()
        self.dirty = False
        return True

    def navigate(self, page: str, initial=False):
        if self._busy or not self.vault:
            return
        if not initial and not self.confirm_note_change():
            return
        self.page = page
        self.nav_selected()
        for widget in self.content.winfo_children():
            widget.destroy()
        self.heading_title.configure(text=page)
        self.heading_subtitle.configure(text={
            "NOTES": "Private written content", "FILES": "Encrypted independent storage",
            "TRASH": "Recover or permanently remove", "LOGS": "Local activity history",
            "SETTINGS": "Backup and security tools"}[page])
        self.search_var = tk.StringVar()
        self._image = None
        if not initial:
            self.vault.log("page_opened", "ui", "", page)
        getattr(self, "show_" + page.lower())()
        self.status_update()

    def search_area(self, parent, placeholder="SEARCH"):
        head = tk.Frame(parent, bg=BLACK)
        head.pack(fill="x", pady=(0, 12))
        label(head, placeholder, 9, RED, bold=True).pack(side="left", padx=(0, 10))
        search = entry(head, self.search_var)
        search.pack(side="left", fill="x", expand=True, ipady=8)
        return search

    def dual_pane(self):
        pane = tk.PanedWindow(self.content, orient="horizontal", bg=BLACK,
                              sashwidth=5, sashrelief="flat", bd=0, showhandle=False)
        pane.pack(fill="both", expand=True)
        left = tk.Frame(pane, bg=BLACK, width=315)
        right = tk.Frame(pane, bg=BLACK, padx=20)
        pane.add(left, minsize=245, width=325)
        pane.add(right, minsize=350)
        return left, right

    def list_with_scroll(self, parent, selectmode="browse"):
        frame = tk.Frame(parent, bg=BLACK)
        frame.pack(fill="both", expand=True)
        lb = listbox(frame, selectmode=selectmode)
        bar = tk.Scrollbar(frame, orient="vertical", command=lb.yview, bg=BLACK,
                           activebackground=RED, troughcolor=BLACK)
        lb.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)
        return lb

    def selection_toolbar(self, parent, list_attribute: str):
        row = tk.Frame(parent, bg=BLACK)
        row.pack(fill="x", pady=(0, 8))
        button(row, "SELECT ALL", lambda: self.select_all(getattr(self, list_attribute)), compact=True).pack(side="left")
        button(row, "CLEAR", lambda: self.clear_selection(getattr(self, list_attribute)), compact=True).pack(side="left", padx=(8, 0))
        self.selection_counter = label(parent, "0 SELECTED   •   CTRL / SHIFT MULTI-SELECT", 9, MUTED, anchor="w")
        self.selection_counter.pack(fill="x", pady=(0, 10))

    def update_selection_counter(self, lb):
        selected = len(lb.curselection())
        if self.selection_counter.winfo_exists():
            self.selection_counter.configure(text=f"{selected} SELECTED   •   CTRL / SHIFT MULTI-SELECT")

    def select_all(self, lb, _event=None):
        lb.selection_set(0, "end")
        lb.event_generate("<<ListboxSelect>>")
        return "break"

    def clear_selection(self, lb, _event=None):
        lb.selection_clear(0, "end")
        lb.event_generate("<<ListboxSelect>>")
        return "break"

    def enable_multi_select_keys(self, lb):
        lb.bind("<Control-a>", lambda event: self.select_all(lb))
        lb.bind("<Escape>", lambda event: self.clear_selection(lb))

    def selected_ids(self, lb, identities):
        return [identities[i] for i in lb.curselection() if i < len(identities)]

    def show_notes(self):
        left, right = self.dual_pane()
        self.search_area(left, "FIND NOTE")
        top = tk.Frame(left, bg=BLACK)
        top.pack(fill="x", pady=(0, 12))
        button(top, "+ NEW NOTE", self.new_note, compact=True).pack(side="left")
        self.selection_toolbar(left, "note_list")
        self.note_list = self.list_with_scroll(left, selectmode="extended")
        self.note_list.bind("<<ListboxSelect>>", self.note_selected)
        self.enable_multi_select_keys(self.note_list)
        self.search_var.trace_add("write", lambda *_: self.refresh_notes())

        commands = tk.Frame(right, bg=BLACK)
        commands.pack(fill="x", pady=(0, 15))
        button(commands, "SAVE  [Ctrl+S]", self.save_note, compact=True).pack(side="left")
        button(commands, "TRASH SELECTED", self.delete_note, compact=True).pack(side="left", padx=(10, 0))
        self.note_state = label(commands, "", 10, MUTED)
        self.note_state.pack(side="right")
        label(right, "TITLE", 9, RED, bold=True, anchor="w").pack(fill="x", pady=(5, 8))
        self.title_var = tk.StringVar()
        self.title_input = entry(right, self.title_var)
        self.title_input.pack(fill="x", ipady=10, pady=(0, 22))
        label(right, "CONTENT", 9, RED, bold=True, anchor="w").pack(fill="x", pady=(0, 8))
        bodyframe = tk.Frame(right, bg=BLACK)
        bodyframe.pack(fill="both", expand=True)
        self.editor = textwidget(bodyframe)
        sb = tk.Scrollbar(bodyframe, command=self.editor.yview)
        self.editor.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.editor.pack(side="left", fill="both", expand=True)
        self.title_var.trace_add("write", lambda *_: self.mark_dirty())
        self.editor.bind("<<Modified>>", self.body_modified)
        self.note_times = label(right, "", 9, MUTED, anchor="w")
        self.note_times.pack(fill="x", pady=(13, 0))
        self.refresh_notes()
        if self.current_note_id and self.current_note_id in self._list_ids:
            self._select_id(self.note_list, self._list_ids, self.current_note_id)
            self.load_note(self.current_note_id, record_view=False)
        else:
            self.load_empty_note()

    def refresh_notes(self):
        if not hasattr(self, "note_list") or not self.note_list.winfo_exists() or not self.vault:
            return
        previous = set(self.selected_ids(self.note_list, self._list_ids))
        query = self.search_var.get().casefold()
        notes = [n for n in self.vault.list_notes() if query in (n["title"] + " " + n["body"]).casefold()]
        self._list_ids = [n["id"] for n in notes]
        self.note_list.delete(0, "end")
        for i, note in enumerate(notes):
            self.note_list.insert("end", f"  {note['title'][:32]}   •   {note['updated_at'][:10]}")
            if note["id"] in previous:
                self.note_list.selection_set(i)
        self.update_selection_counter(self.note_list)

    def _select_id(self, lb, identities, identity):
        if identity in identities:
            i = identities.index(identity)
            lb.selection_clear(0, "end")
            lb.selection_set(i)
            lb.see(i)
            self.update_selection_counter(lb)

    def note_selected(self, _event=None):
        self.update_selection_counter(self.note_list)
        choice = self.note_list.curselection()
        if len(choice) != 1:
            return
        identity = self._list_ids[choice[0]]
        if identity == self.current_note_id:
            return
        if not self.confirm_note_change():
            self._select_id(self.note_list, self._list_ids, self.current_note_id)
            return
        self.load_note(identity)

    def load_note(self, identity: str, record_view=True):
        note = self.vault.note(identity)
        self.current_note_id = identity
        self.loading_editor = True
        self.title_input.configure(state="normal")
        if self._autosave_handle is not None:
            self.root.after_cancel(self._autosave_handle)
            self._autosave_handle = None
        self.title_var.set(note["title"])
        self._last_saved_title = note["title"]
        self._last_saved_body = note["body"]
        self.editor.configure(state="normal")
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", note["body"])
        self.editor.edit_modified(False)
        self.note_state.configure(text="SAVED")
        self.note_times.configure(text=f"CREATED: {note['created_at']}    •    LAST EDITED: {note['updated_at']}")
        self.loading_editor = False
        self.dirty = False
        if record_view:
            self.vault.log("note_opened", "note", identity, note["title"])
            self.status_update()

    def load_empty_note(self):
        self.current_note_id = None
        self.loading_editor = True
        if self._autosave_handle is not None:
            self.root.after_cancel(self._autosave_handle)
            self._autosave_handle = None
        self.title_var.set("")
        self._last_saved_title = ""
        self._last_saved_body = ""
        self.editor.delete("1.0", "end")
        self.editor.edit_modified(False)
        self.note_times.configure(text="Create a new note or choose one from the list.")
        self.note_state.configure(text="NO NOTE SELECTED")
        self.title_input.configure(state="disabled", disabledbackground=BLACK, disabledforeground=MUTED)
        self.editor.configure(state="disabled")
        self.loading_editor = False
        self.dirty = False

    def mark_dirty(self):
        if self.loading_editor or self.current_note_id is None:
            return
        # Text's <<Modified>> can be queued by programmatic edits; compare to
        # the last saved state rather than treating every callback as a real edit.
        title = self.title_var.get().strip() or "Untitled note"
        body = self.editor.get("1.0", "end-1c")
        if title == self._last_saved_title and body == self._last_saved_body:
            self.dirty = False
            self.note_state.configure(text="SAVED", fg=MUTED)
            return
        self.dirty = True
        self.note_state.configure(text="AUTOSAVING…", fg=RED)
        if self._autosave_handle is not None:
            self.root.after_cancel(self._autosave_handle)
        note_id = self.current_note_id
        self._autosave_handle = self.root.after(2200, lambda: self.autosave_note(note_id))

    def autosave_note(self, identity):
        self._autosave_handle = None
        if self.vault and self.page == "NOTES" and self.current_note_id == identity and self.dirty and not self._busy:
            self.save_note()

    def body_modified(self, _event):
        if self.editor.edit_modified():
            self.editor.edit_modified(False)
            self.mark_dirty()

    def new_note(self):
        if not self.confirm_note_change():
            return
        identity = self.vault.create_note()
        self.current_note_id = identity
        self.refresh_notes()
        self.load_note(identity, record_view=False)
        self._select_id(self.note_list, self._list_ids, identity)
        self.title_input.focus_set()
        self.title_input.selection_range(0, "end")
        self.status_update("NOTE CREATED")

    def save_note(self) -> bool:
        if not self.vault or self.page != "NOTES" or not self.current_note_id:
            return True
        try:
            saved = self.vault.save_note(self.current_note_id, self.title_var.get(), self.editor.get("1.0", "end-1c"))
            self.dirty = False
            self._last_saved_title = self.title_var.get().strip() or "Untitled note"
            self._last_saved_body = self.editor.get("1.0", "end-1c")
            self.editor.edit_modified(False)
            if self._autosave_handle is not None:
                self.root.after_cancel(self._autosave_handle)
                self._autosave_handle = None
            self.note_state.configure(text="SAVED", fg=MUTED)
            item = self.vault.note(self.current_note_id)
            self.note_times.configure(text=f"CREATED: {item['created_at']}    •    LAST EDITED: {item['updated_at']}")
            self.refresh_notes()
            self.status_update("NOTE SAVED" if saved else "NO CHANGES")
            return True
        except (VaultError, OSError) as exc:
            messagebox.showerror("Save failed", str(exc))
            return False

    def delete_note(self):
        ids = self.selected_ids(self.note_list, self._list_ids)
        if not ids or not self.confirm_note_change():
            return
        if not messagebox.askyesno("Move notes to trash", f"Move {len(ids)} selected note(s) to Trash?\n\nThey can be restored later."):
            return
        try:
            changed = self.vault.batch_move_to_trash([("note", identity) for identity in ids])
        except (VaultError, OSError) as exc:
            messagebox.showerror("Move to trash failed", str(exc))
            return
        if self.current_note_id in ids:
            self.current_note_id = None
            self.load_empty_note()
        self.refresh_notes()
        self.status_update(f"{changed} NOTES MOVED TO TRASH")

    def show_files(self):
        left, right = self.dual_pane()
        self.search_area(left, "FIND FILE")
        actions = tk.Frame(left, bg=BLACK)
        actions.pack(fill="x", pady=(0, 12))
        button(actions, "+ FILES", self.import_files, compact=True).pack(side="left")
        button(actions, "+ FOLDER", self.import_folder, compact=True).pack(side="left", padx=(8, 0))
        self.selection_toolbar(left, "file_list")
        self.file_list = self.list_with_scroll(left, selectmode="extended")
        self.file_list.bind("<<ListboxSelect>>", self.file_selected)
        self.enable_multi_select_keys(self.file_list)
        self.search_var.trace_add("write", lambda *_: self.refresh_files())
        buttons = tk.Frame(right, bg=BLACK)
        buttons.pack(fill="x", pady=(0, 24))
        button(buttons, "EXPORT ONE", self.export_file, compact=True).pack(side="left")
        button(buttons, "TRASH SELECTED", self.delete_file, compact=True).pack(side="left", padx=(12, 0))
        self.file_info = label(right, "Select a file to view its properties.", 11, WHITE, anchor="nw", justify="left")
        self.file_info.pack(fill="x", pady=(0, 22))
        self.preview_box = tk.Frame(right, bg=BLACK, highlightbackground=RED, highlightthickness=1)
        self.preview_box.pack(fill="both", expand=True)
        self.preview_label = label(self.preview_box, "IMAGE PREVIEW\n\nEncrypted files remain on disk until exported.",
                                   11, MUTED, justify="center", wraplength=430)
        self.preview_label.pack(expand=True, fill="both", padx=15, pady=15)
        self.refresh_files()
        if self.current_file_id and self.current_file_id in self._list_ids:
            self._select_id(self.file_list, self._list_ids, self.current_file_id)
            self.load_file(self.current_file_id, record_view=False)

    def refresh_files(self):
        if not hasattr(self, "file_list") or not self.file_list.winfo_exists() or not self.vault:
            return
        previous = set(self.selected_ids(self.file_list, self._list_ids))
        query = self.search_var.get().casefold()
        items = [f for f in self.vault.list_files() if query in f["path"].casefold()]
        self._list_ids = [f["id"] for f in items]
        self.file_list.delete(0, "end")
        for i, item in enumerate(items):
            self.file_list.insert("end", f"  {item['name'][:32]}   •   {size_text(item['size'])}")
            if item["id"] in previous:
                self.file_list.selection_set(i)
        self.update_selection_counter(self.file_list)

    def file_selected(self, _event=None):
        self.update_selection_counter(self.file_list)
        choice = self.file_list.curselection()
        if len(choice) > 1:
            self.current_file_id = None
            self._image = None
            self.file_info.configure(text=f"{len(choice)} FILES SELECTED\n\nMove them to Trash together, or select one for a preview or export.")
            self.preview_label.configure(image="", text="MULTIPLE FILES SELECTED")
            return
        if len(choice) == 1:
            identity = self._list_ids[choice[0]]
            if identity != self.current_file_id:
                self.load_file(identity)
        else:
            self.current_file_id = None
            self._image = None
            self.file_info.configure(text="Select a file to view its properties.")
            self.preview_label.configure(image="", text="IMAGE PREVIEW\n\nEncrypted files remain on disk until exported.")

    def load_file(self, identity, record_view=True):
        item = self.vault.file(identity)
        self.current_file_id = identity
        media, _ = mimetypes.guess_type(item["name"])
        kind = media or "application/octet-stream"
        self.file_info.configure(text=(f"NAME       {item['name']}\n\n"
                                       f"STORED     {item['path']}\n\n"
                                       f"TYPE       {kind}\n\n"
                                       f"SIZE       {size_text(item['size'])}\n\n"
                                       f"IMPORTED   {item['added_at']}"), wraplength=560)
        self._image = None
        self.preview_label.configure(image="", text="Preview is available for supported image formats.\nAll other data can be exported when needed.")
        if kind.startswith("image/") and item["size"] <= 25 * 1024 * 1024:
            try:
                data = self.vault.file_bytes(identity)
                if Image:
                    with Image.open(io.BytesIO(data)) as inp:
                        image = inp.copy()
                    image.thumbnail((640, 360))
                    self._image = ImageTk.PhotoImage(image)
                else:
                    self._image = tk.PhotoImage(data=data)
                self.preview_label.configure(image=self._image, text="")
            except Exception as exc:
                self.preview_label.configure(text=f"Image preview unavailable.\n{exc}")
        if record_view:
            self.vault.log("file_viewed", "file", identity, item["path"])
            self.status_update()

    def import_files(self):
        names = filedialog.askopenfilenames(title="Copy files into the encrypted vault")
        if not names:
            return
        def task(update):
            count, errors = 0, []
            for i, name in enumerate(names, 1):
                update(f"File {i}/{len(names)}: {Path(name).name}")
                try:
                    self.vault.import_file(name, progress=update)
                    count += 1
                except (VaultError, OSError) as exc:
                    errors.append(f"{Path(name).name}: {exc}")
            return count, errors
        self.job("ENCRYPTING AND IMPORTING FILES", task, self.import_complete)

    def import_folder(self):
        folder = filedialog.askdirectory(title="Copy folder contents and project files into the vault")
        if folder:
            self.job("ENCRYPTING FOLDER", lambda update: self.vault.import_folder(folder, update), self.import_complete)

    def import_complete(self, result):
        count, errors = result
        self.current_file_id = None
        self.navigate("FILES")
        self.status_update(f"IMPORTED {count} FILES")
        if errors:
            preview = "\n".join(errors[:20])
            messagebox.showwarning("Some imports failed", f"Imported {count} file(s).\n\n{preview}")

    def export_file(self):
        ids = self.selected_ids(self.file_list, self._list_ids)
        if len(ids) != 1:
            messagebox.showinfo("Export file", "Select exactly one file to export. You can select multiple files for Trash.")
            return
        identity = ids[0]
        item = self.vault.file(identity)
        dest = filedialog.asksaveasfilename(title="Export decrypted file", initialfile=item["name"])
        if not dest:
            return
        if Path(dest).exists() and not messagebox.askyesno("Overwrite file?", "Overwrite the existing file?"):
            return
        self.job("EXPORTING DECRYPTED FILE", lambda update: self.vault.export_file(identity, dest, update),
                 lambda _: self.status_update("FILE EXPORTED AS PLAINTEXT"))

    def delete_file(self):
        ids = self.selected_ids(self.file_list, self._list_ids)
        if not ids:
            return
        if not messagebox.askyesno("Move files to trash", f"Move {len(ids)} selected file(s) to Trash?\n\nEncrypted file contents will remain stored for recovery."):
            return
        try:
            changed = self.vault.batch_move_to_trash([("file", identity) for identity in ids])
        except (VaultError, OSError) as exc:
            messagebox.showerror("Move to trash failed", str(exc))
            return
        if self.current_file_id in ids:
            self.current_file_id = None
        self.navigate("FILES")
        self.status_update(f"{changed} FILES MOVED TO TRASH")

    def show_trash(self):
        header = tk.Frame(self.content, bg=BLACK)
        header.pack(fill="x", pady=(0, 14))
        button(header, "RESTORE SELECTED", self.restore_trash, compact=True).pack(side="left")
        button(header, "DELETE PERMANENTLY", self.purge_trash, compact=True).pack(side="left", padx=(10, 0))
        label(self.content, "Deleted items remain encrypted until permanently removed.", 10, MUTED, anchor="w").pack(fill="x", pady=(0, 12))
        self.selection_toolbar(self.content, "trash_list")
        self.trash_list = self.list_with_scroll(self.content, selectmode="extended")
        self.trash_list.bind("<<ListboxSelect>>", lambda _event: self.update_selection_counter(self.trash_list))
        self.enable_multi_select_keys(self.trash_list)
        notes = [("note", x) for x in self.vault.list_notes(trashed=True)]
        files = [("file", x) for x in self.vault.list_files(trashed=True)]
        items = sorted(notes + files, key=lambda v: v[1]["trashed_at"], reverse=True)
        self._trash_ids = [(kind, item["id"]) for kind, item in items]
        for kind, item in items:
            name = item.get("title", item.get("path", ""))
            self.trash_list.insert("end", f"  [{kind.upper()}]  {name[:55]}   •   {item['trashed_at'][:19]}")

    def selected_trash(self):
        return self.selected_ids(self.trash_list, self._trash_ids)

    def restore_trash(self):
        targets = self.selected_trash()
        if not targets:
            return
        try:
            count = self.vault.batch_restore(targets)
        except (VaultError, OSError) as exc:
            messagebox.showerror("Restore failed", str(exc))
            return
        self.navigate("TRASH")
        self.status_update(f"{count} ITEMS RESTORED")

    def purge_trash(self):
        targets = self.selected_trash()
        if not targets:
            return
        if not messagebox.askyesno("Permanent deletion", f"Permanently delete {len(targets)} selected item(s) from the vault?\n\nThis cannot be undone. Existing backups or filesystem snapshots may still contain them.", icon="warning"):
            return
        try:
            count = self.vault.batch_permanently_delete(targets)
        except (VaultError, OSError) as exc:
            messagebox.showerror("Permanent deletion failed", str(exc))
            return
        self.navigate("TRASH")
        self.status_update(f"{count} ITEMS PERMANENTLY REMOVED")

    def show_logs(self):
        left, right = self.dual_pane()
        self.search_area(left, "SEARCH EVENTS")
        self.log_list = self.list_with_scroll(left)
        self.log_list.bind("<<ListboxSelect>>", self.log_selected)
        self.search_var.trace_add("write", lambda *_: self.refresh_logs())
        label(right, "EVENT DETAILS", 10, RED, bold=True, anchor="w").pack(fill="x", pady=(0, 13))
        self.log_details = textwidget(right, height=16)
        self.log_details.pack(fill="both", expand=True)
        self.log_details.configure(state="disabled")
        self.refresh_logs()

    def refresh_logs(self):
        if not hasattr(self, "log_list") or not self.log_list.winfo_exists():
            return
        self._log_rows = self.vault.logs(self.search_var.get())
        self.log_list.delete(0, "end")
        for event in self._log_rows:
            self.log_list.insert("end", f"  {event['at'][:16]}   {event['action'].upper()}")

    def log_selected(self, _event=None):
        choice = self.log_list.curselection()
        if not choice:
            return
        info = json.dumps(self._log_rows[choice[0]], ensure_ascii=False, indent=2)
        self.log_details.configure(state="normal")
        self.log_details.delete("1.0", "end")
        self.log_details.insert("1.0", info)
        self.log_details.configure(state="disabled")

    def settings_row(self, title, description, action, func):
        item = tk.Frame(self.content, bg=BLACK)
        item.pack(fill="x", pady=14)
        text = tk.Frame(item, bg=BLACK)
        text.pack(side="left", fill="x", expand=True)
        label(text, title, 13, WHITE, bold=True, anchor="w").pack(fill="x")
        label(text, description, 10, MUTED, anchor="w", wraplength=630, justify="left").pack(fill="x", pady=(5, 0))
        button(item, action, func, compact=True).pack(side="right")
        line(self.content).pack(fill="x")

    def show_settings(self):
        stats = self.vault.stats()
        label(self.content, "YOUR DATA", 14, RED, bold=True, anchor="w").pack(fill="x", pady=(0, 7))
        label(self.content, f"{stats['notes']} notes   •   {stats['files']} files   •   {size_text(stats['bytes'])} source data   •   {stats['logs']} events",
              11, WHITE, anchor="w").pack(fill="x")
        label(self.content, f"Vault folder:  {self.vault_path}", 9, MUTED, anchor="w", wraplength=900, justify="left").pack(fill="x", pady=(9, 22))
        line(self.content).pack(fill="x")
        self.settings_row("Encrypted backup", "All active and trashed data, notes and logs. Portable, requires this vault password. ZIP / TAR.GZ / TAR.",
                          "EXPORT BACKUP", self.backup_dialog)
        self.settings_row("Readable ZIP", "Exports active notes, active files and logs as UNENCRYPTED plaintext. Use only when you need readable copies.",
                          "EXPORT PLAINTEXT", self.readable_dialog)
        self.settings_row("Verify stored files", "Decrypt and authenticate every saved file to check AES-GCM tags and recorded byte sizes.",
                          "VERIFY INTEGRITY", self.verify_dialog)
        self.settings_row("Restore encrypted backup", "Extract a backup into a separate empty folder, then unlock it with the original password.",
                          "RESTORE BACKUP", self.restore_backup_dialog)
        self.settings_row("Lock application", "Clear the current session. The app also locks after 15 minutes without interaction.",
                          "LOCK NOW", self.lock)
        label(self.content, "Password recovery is not possible. Keep multiple encrypted backups and remember your password.",
              10, RED, anchor="w", wraplength=760).pack(fill="x", pady=23)

    def backup_dialog(self):
        filename = filedialog.asksaveasfilename(title="Export encrypted vault backup", defaultextension=".zip",
                                                 initialfile="kayralrics-vault-encrypted.zip", filetypes=[
                                                     ("ZIP archive", "*.zip"), ("TAR.GZ archive", "*.tar.gz"), ("TAR archive", "*.tar")])
        if not filename:
            return
        if Path(filename).exists() and not messagebox.askyesno("Overwrite backup?", "Replace existing backup?"):
            return
        self.job("CREATING ENCRYPTED BACKUP", lambda update: self.vault.export_encrypted_backup(filename, update),
                 lambda _: messagebox.showinfo("Backup complete", "Encrypted backup written successfully. Keep your password."))

    def readable_dialog(self):
        if not messagebox.askyesno("Unencrypted export", "WARNING: This ZIP will contain UNENCRYPTED notes, files and logs.\n\nAnyone who gets the ZIP can read it. Continue?", icon="warning"):
            return
        filename = filedialog.asksaveasfilename(title="Export READABLE plain ZIP", defaultextension=".zip",
                                                 initialfile="kayralrics-readable-UNENCRYPTED.zip", filetypes=[("ZIP", "*.zip")])
        if filename:
            if Path(filename).exists() and not messagebox.askyesno("Overwrite export?", "Replace existing export?"):
                return
            self.job("CREATING UNENCRYPTED ZIP", lambda update: self.vault.export_readable_zip(filename, update),
                     lambda _: messagebox.showwarning("Plaintext ZIP created", "This exported ZIP is NOT encrypted. Store it carefully."))

    def verify_dialog(self):
        def complete(result):
            count, issues = result
            if issues:
                messagebox.showerror("Integrity problems", f"Checked {count} file(s).\n\n" + "\n".join(issues[:20]))
            else:
                messagebox.showinfo("Integrity verified", f"All {count} encrypted file(s) passed authentication and size checks.")
            self.status_update("INTEGRITY CHECK COMPLETE")
        self.job("VERIFYING ENCRYPTED FILES", lambda update: self.vault.verify(update), complete)

    def job(self, title, fn, complete):
        if self._busy:
            return
        self._busy = True
        q = queue.Queue()
        dialog = tk.Toplevel(self.root, bg=BLACK)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.geometry("580x200")
        dialog.resizable(False, False)
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        tk.Label(dialog, text=title, bg=BLACK, fg=RED, font=(FONT, 14, "bold")).pack(pady=(30, 18))
        progress_label = label(dialog, "WORKING LOCALLY…", 10, WHITE, wraplength=530)
        progress_label.pack(padx=20, pady=(0, 13))
        style = ttk.Style(dialog)
        style.theme_use("clam")
        style.configure("Vault.Horizontal.TProgressbar", troughcolor=BLACK, background=RED,
                        bordercolor=RED, lightcolor=RED, darkcolor=RED)
        bar = ttk.Progressbar(dialog, mode="indeterminate", style="Vault.Horizontal.TProgressbar", length=500)
        bar.pack(pady=(0, 10))
        bar.start(15)
        dialog.update_idletasks()
        dialog.geometry(f"+{self.root.winfo_rootx() + max(0, (self.root.winfo_width() - 580) // 2)}+{self.root.winfo_rooty() + max(0, (self.root.winfo_height() - 200) // 2)}")
        dialog.grab_set()

        def worker():
            try:
                result = fn(lambda s: q.put(("update", str(s))))
                q.put(("done", result))
            except BaseException as exc:
                q.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

        def poll():
            latest_progress = None
            completed = None
            while not q.empty():
                kind, payload = q.get_nowait()
                if kind == "update":
                    latest_progress = payload
                else:
                    completed = (kind, payload)
            if latest_progress is not None:
                progress_label.configure(text=latest_progress[:115])
            if completed:
                bar.stop()
                dialog.grab_release()
                dialog.destroy()
                self._busy = False
                if completed[0] == "error":
                    messagebox.showerror("Operation failed", completed[1], parent=self.root)
                else:
                    try:
                        complete(completed[1])
                    except Exception as exc:
                        messagebox.showerror("Display update error", str(exc))
                if self.vault and not self.vault.locked:
                    self.status_update()
            else:
                self.root.after(90, poll)
        self.root.after(90, poll)

    def lock(self):
        if self._busy:
            return
        if not self.confirm_note_change():
            return
        if self._autosave_handle is not None:
            self.root.after_cancel(self._autosave_handle)
            self._autosave_handle = None
        if self.vault:
            try:
                self.vault.lock()
            except (VaultError, OSError) as exc:
                messagebox.showerror("Lock failed", str(exc))
                return
        self.welcome()

    def auto_lock_check(self):
        if self.vault and not self.vault.locked and not self._busy and time.monotonic() - self._last_activity >= 900:
            if self.dirty and self.page == "NOTES" and not self.save_note():
                # Do not discard an unsaved note if the disk refuses the write.
                self.root.after(30_000, self.auto_lock_check)
                return
            self.lock()
        self.root.after(30_000, self.auto_lock_check)

    def close(self):
        if self._busy:
            messagebox.showinfo("Operation in progress", "An import/export is running. Finish it before closing the vault.")
            return
        if not self.confirm_note_change():
            return
        if self.vault and not self.vault.locked:
            try:
                self.vault.lock()
            except Exception as exc:
                if not messagebox.askyesno("Saving failed", f"Could not save the closing event: {exc}\n\nExit anyway?"):
                    return
        self.root.destroy()

    def shortcut_save(self, _event=None):
        if self.vault and self.page == "NOTES" and not self._busy:
            self.save_note()
        return "break"

    def shortcut_new(self, _event=None):
        if self.vault and self.page == "NOTES" and not self._busy:
            self.new_note()
        return "break"

    def shortcut_lock(self, _event=None):
        if self.vault and not self._busy:
            self.lock()
        return "break"

    def shortcut_find(self, _event=None):
        if self.vault and self.page in ("NOTES", "FILES", "LOGS"):
            # Search boxes share one local state variable.
            for w in self.content.winfo_children():
                for descendant in w.winfo_children():
                    for child in descendant.winfo_children():
                        if isinstance(child, tk.Entry):
                            child.focus_set()
                            return "break"
        return "break"

    def shortcut_refresh(self, _event=None):
        if self.vault and not self._busy:
            if self.page == "NOTES":
                self.refresh_notes()
            elif self.page == "FILES":
                self.refresh_files()
            elif self.page == "LOGS":
                self.refresh_logs()
        return "break"


def main():
    if os.name == "posix":
        os.umask(0o077)
    root = tk.Tk()
    Application(root)
    root.mainloop()


if __name__ == "__main__":
    main()
