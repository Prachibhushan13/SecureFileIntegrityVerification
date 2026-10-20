"""
gui/history_view.py - Verification History and Audit Log View
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Provides a dedicated interface for reviewing, searching, filtering,
and exporting verification history logs to CSV format.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional

from gui.styles import (
    COLOR_BG_DARK, COLOR_CARD_BG, COLOR_BORDER, COLOR_INPUT_BG,
    COLOR_TEXT_WHITE, COLOR_TEXT_MUTED, COLOR_PRIMARY, COLOR_SUCCESS,
    COLOR_DANGER, COLOR_WARNING, FONT_HEADING, FONT_BODY, FONT_BODY_BOLD,
    FONT_HASH, FONT_SUBTITLE
)
from database import Database
from report_generator import export_history_to_csv
from integrity_service import STATUS_VERIFIED, STATUS_MODIFIED


class HistoryView(tk.Frame):
    """Encapsulates the history filter, search, table, and CSV export."""

    def __init__(self, parent: tk.Widget, db: Database):
        super().__init__(parent, bg=COLOR_BG_DARK)
        self.db = db
        self._build_ui()
        self.refresh_history()

    def _build_ui(self) -> None:
        # Top Controls Bar: Filter, Search, Export, Clear
        controls_frame = tk.Frame(self, bg=COLOR_CARD_BG, padx=16, pady=12)
        controls_frame.pack(fill="x", padx=16, pady=(16, 8))

        # Status Filter
        tk.Label(controls_frame, text="Filter Status:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(side="left", padx=(0, 6))

        self.status_var = tk.StringVar(value="ALL")
        status_options = [
            "ALL",
            "INTEGRITY VERIFIED",
            "FILE MODIFIED — HASH MISMATCH",
            "FILE NOT REGISTERED",
            "FILE NOT FOUND",
            "VERIFICATION ERROR"
        ]
        self.filter_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.status_var,
            values=status_options,
            state="readonly",
            width=24
        )
        self.filter_combo.pack(side="left", padx=(0, 16))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_history())

        # Search Box
        tk.Label(controls_frame, text="Search File:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            controls_frame,
            textvariable=self.search_var,
            font=FONT_BODY,
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_WHITE,
            insertbackground=COLOR_TEXT_WHITE,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            width=20
        )
        self.search_entry.pack(side="left", padx=(0, 8))
        self.search_entry.bind("<Return>", lambda e: self.refresh_history())

        btn_search = ttk.Button(controls_frame, text="Search", style="Primary.TButton", command=self.refresh_history)
        btn_search.pack(side="left", padx=(0, 6))

        btn_reset = ttk.Button(controls_frame, text="Reset", style="Secondary.TButton", command=self._reset_filters)
        btn_reset.pack(side="left", padx=(0, 16))

        # Right Action Buttons: Export & Clear
        btn_clear = ttk.Button(controls_frame, text="Clear Logs", style="Danger.TButton", command=self._clear_history)
        btn_clear.pack(side="right", padx=(6, 0))

        btn_export = ttk.Button(controls_frame, text="Export CSV", style="Primary.TButton", command=self._export_csv)
        btn_export.pack(side="right", padx=6)

        btn_refresh = ttk.Button(controls_frame, text="Refresh", style="Secondary.TButton", command=self.refresh_history)
        btn_refresh.pack(side="right", padx=6)

        # History Treeview Table
        table_container = tk.Frame(self, bg=COLOR_CARD_BG, padx=8, pady=8)
        table_container.pack(fill="both", expand=True, padx=16, pady=4)

        columns = ("id", "timestamp", "filename", "status", "expected_hash", "actual_hash")
        self.tree = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=14
        )

        self.tree.heading("id", text="ID")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("filename", text="Target File")
        self.tree.heading("status", text="Verification Status")
        self.tree.heading("expected_hash", text="Expected Hash (SHA-256)")
        self.tree.heading("actual_hash", text="Actual Hash (SHA-256)")

        self.tree.column("id", width=45, anchor="center")
        self.tree.column("timestamp", width=145, anchor="center")
        self.tree.column("filename", width=180, anchor="w")
        self.tree.column("status", width=210, anchor="center")
        self.tree.column("expected_hash", width=160, anchor="w")
        self.tree.column("actual_hash", width=160, anchor="w")

        # Color tags
        self.tree.tag_configure("VERIFIED", foreground=COLOR_SUCCESS)
        self.tree.tag_configure("MODIFIED", foreground=COLOR_DANGER)
        self.tree.tag_configure("WARNING", foreground=COLOR_WARNING)

        vsb = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select_record)

        # Bottom Detail Card for selected entry
        self.detail_card = tk.Frame(self, bg=COLOR_CARD_BG, padx=16, pady=10)
        self.detail_card.pack(fill="x", padx=16, pady=(6, 16))

        self.lbl_detail_title = tk.Label(
            self.detail_card,
            text="Selected Record Details (Click a row above to inspect full hashes):",
            font=FONT_BODY_BOLD,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD_BG
        )
        self.lbl_detail_title.pack(anchor="w")

        self.detail_text = tk.Text(
            self.detail_card,
            height=4,
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_WHITE,
            font=FONT_HASH,
            relief="flat",
            wrap="word",
            state="disabled",
            highlightbackground=COLOR_BORDER,
            highlightthickness=1
        )
        self.detail_text.pack(fill="x", pady=(4, 0))

    def _reset_filters(self) -> None:
        self.status_var.set("ALL")
        self.search_var.set("")
        self.refresh_history()

    def refresh_history(self) -> None:
        """Loads verification records from SQLite and populates Treeview."""
        status_filter = self.status_var.get()
        search_term = self.search_var.get()

        records = self.db.get_history(status_filter=status_filter, search_term=search_term, limit=300)

        for item in self.tree.get_children():
            self.tree.delete(item)

        for rec in records:
            path_obj = Path(rec["file_path"])
            fname = path_obj.name
            status = rec["verification_result"]

            tag = "WARNING"
            if status == STATUS_VERIFIED:
                tag = "VERIFIED"
            elif status == STATUS_MODIFIED:
                tag = "MODIFIED"

            exp = rec["expected_hash"][:16] + "..." if rec["expected_hash"] else "None"
            act = rec["actual_hash"][:16] + "..." if rec["actual_hash"] else "None"

            self.tree.insert(
                "",
                "end",
                iid=str(rec["id"]),
                values=(
                    rec["id"],
                    rec["timestamp"],
                    fname,
                    status,
                    exp,
                    act
                ),
                tags=(tag,)
            )

    def _on_select_record(self, event) -> None:
        selected = self.tree.selection()
        if not selected:
            return

        rec_id = int(selected[0])
        records = self.db.get_history()
        match = next((r for r in records if r["id"] == rec_id), None)
        if not match:
            return

        info_lines = [
            f"File Path    : {match['file_path']}",
            f"Result       : {match['verification_result']}  |  Timestamp: {match['timestamp']}",
            f"Expected Hash: {match['expected_hash'] or 'None'}",
            f"Actual Hash  : {match['actual_hash'] or 'None'}"
        ]
        if match.get("error_details"):
            info_lines.append(f"Diagnostics  : {match['error_details']}")

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", "\n".join(info_lines))
        self.detail_text.configure(state="disabled")

    def _export_csv(self) -> None:
        records = self.db.get_history(
            status_filter=self.status_var.get(),
            search_term=self.search_var.get(),
            limit=5000
        )
        if not records:
            messagebox.showinfo("Export CSV", "No history records to export.", parent=self)
            return

        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Export Verification History",
            initialfile="verification_audit_log.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if dest:
            try:
                export_history_to_csv(records, dest)
                messagebox.showinfo("Success", f"Exported {len(records)} records to:\n{dest}", parent=self)
            except Exception as e:
                messagebox.showerror("Export Failed", f"Could not export CSV: {e}", parent=self)

    def _clear_history(self) -> None:
        confirmed = messagebox.askyesno(
            "Clear History",
            "Are you sure you want to delete all verification history audit logs?\nThis action cannot be undone.",
            parent=self,
            icon="warning"
        )
        if confirmed:
            count = self.db.clear_history()
            self.refresh_history()
            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.configure(state="disabled")
            messagebox.showinfo("History Cleared", f"Deleted {count} history records.", parent=self)
