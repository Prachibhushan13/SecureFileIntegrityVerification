"""
gui/dashboard.py - Main Desktop Dashboard Application Window
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Provides the primary user interface containing:
- Summary KPI Cards (Registered Files, Clean Verifications, Detected Tampering, Total Attempts)
- Quick Verification & File Registration panel
- Registered Baseline Management with Treeview
- Integration with Verification History and Avalanche Effect Labs
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional, List

from database import Database
from hashing import calculate_file_sha256, HashingError
from integrity_service import (
    IntegrityService, VerificationResult,
    STATUS_VERIFIED, STATUS_MODIFIED, STATUS_NOT_REGISTERED,
    STATUS_NOT_FOUND, STATUS_ERROR
)
from report_generator import generate_text_report, generate_batch_summary_report
from gui.styles import (
    configure_app_styles, COLOR_BG_DARK, COLOR_CARD_BG, COLOR_BORDER,
    COLOR_INPUT_BG, COLOR_TEXT_WHITE, COLOR_TEXT_MUTED, COLOR_PRIMARY,
    COLOR_SUCCESS, COLOR_DANGER, COLOR_WARNING, COLOR_SUCCESS_BG,
    COLOR_DANGER_BG, COLOR_WARNING_BG, FONT_TITLE, FONT_SUBTITLE,
    FONT_HEADING, FONT_BODY, FONT_BODY_BOLD, FONT_HASH, FONT_STAT_NUMBER,
    FONT_STAT_LABEL
)
from gui.dialogs import VerificationResultDialog, show_baseline_overwrite_warning
from gui.history_view import HistoryView
from gui.avalanche_view import AvalancheView


class DashboardApp(tk.Tk):
    """Main Application Window for Secure File Integrity Verification."""

    def __init__(self, db: Optional[Database] = None):
        super().__init__()
        self.title("Secure File Integrity Verification Using SHA-256")
        self.geometry("1100x740")
        self.minsize(980, 640)

        # Initialize backend services
        self.db = db or Database()
        self.service = IntegrityService(self.db)

        # Track active verified result
        self.last_result: Optional[VerificationResult] = None

        # Apply design tokens
        configure_app_styles(self)

        # Build application structure
        self._build_header()
        self._build_stat_cards()
        self._build_notebook()

        # Load initial data
        self.refresh_all_data()

    # =========================================================================
    # Header & Metric Cards
    # =========================================================================

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=COLOR_BG_DARK, padx=20, pady=12)
        header.pack(fill="x")

        # Title & Subtitle
        left_box = tk.Frame(header, bg=COLOR_BG_DARK)
        left_box.pack(side="left")

        lbl_title = tk.Label(
            left_box,
            text="Secure File Integrity Verification",
            font=FONT_TITLE,
            fg=COLOR_TEXT_WHITE,
            bg=COLOR_BG_DARK
        )
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(
            left_box,
            text="Cryptography & Network Security  |  SHA-256 Baseline Integrity & Tamper Detection",
            font=FONT_SUBTITLE,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_BG_DARK
        )
        lbl_sub.pack(anchor="w", pady=(2, 0))

        # Quick batch actions on top right
        right_box = tk.Frame(header, bg=COLOR_BG_DARK)
        right_box.pack(side="right")

        btn_verify_all = ttk.Button(
            right_box,
            text="Verify All Registered",
            style="Primary.TButton",
            command=self._on_verify_all_registered
        )
        btn_verify_all.pack(side="left", padx=4)

        btn_refresh = ttk.Button(
            right_box,
            text="Refresh Dashboard",
            style="Secondary.TButton",
            command=self.refresh_all_data
        )
        btn_refresh.pack(side="left", padx=4)

    def _build_stat_cards(self) -> None:
        cards_container = tk.Frame(self, bg=COLOR_BG_DARK, padx=20, pady=4)
        cards_container.pack(fill="x")

        cards_container.columnconfigure(0, weight=1)
        cards_container.columnconfigure(1, weight=1)
        cards_container.columnconfigure(2, weight=1)
        cards_container.columnconfigure(3, weight=1)

        # Card 1: Registered Files
        self.card_registered, self.lbl_count_registered = self._create_single_card(
            cards_container, 0, "REGISTERED BASELINES", "0", COLOR_PRIMARY
        )

        # Card 2: Clean Verifications
        self.card_verified, self.lbl_count_verified = self._create_single_card(
            cards_container, 1, "INTEGRITY VERIFIED", "0", COLOR_SUCCESS
        )

        # Card 3: Tampering / Mismatches Detected
        self.card_tampered, self.lbl_count_tampered = self._create_single_card(
            cards_container, 2, "TAMPERING DETECTED", "0", COLOR_DANGER
        )

        # Card 4: Total Checks Executed
        self.card_total, self.lbl_count_total = self._create_single_card(
            cards_container, 3, "TOTAL AUDIT CHECKS", "0", COLOR_TEXT_WHITE
        )

    def _create_single_card(
        self, parent: tk.Widget, col: int, label: str, initial_val: str, num_color: str
    ):
        frame = tk.Frame(parent, bg=COLOR_CARD_BG, padx=16, pady=12, relief="flat")
        frame.grid(row=0, column=col, padx=6, sticky="ew")

        lbl_num = tk.Label(frame, text=initial_val, font=FONT_STAT_NUMBER, fg=num_color, bg=COLOR_CARD_BG)
        lbl_num.pack(anchor="w")

        lbl_text = tk.Label(frame, text=label, font=FONT_STAT_LABEL, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG)
        lbl_text.pack(anchor="w", pady=(2, 0))

        return frame, lbl_num

    # =========================================================================
    # Notebook & Views
    # =========================================================================

    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(10, 16))

        # Tab 1: Verification & Quick Check
        self.tab_verify = tk.Frame(self.notebook, bg=COLOR_BG_DARK)
        self.notebook.add(self.tab_verify, text="  Verification & Quick Actions  ")
        self._build_verify_tab(self.tab_verify)

        # Tab 2: Registered Baselines Management
        self.tab_baselines = tk.Frame(self.notebook, bg=COLOR_BG_DARK)
        self.notebook.add(self.tab_baselines, text="  Registered Baseline Files  ")
        self._build_baselines_tab(self.tab_baselines)

        # Tab 3: Verification Audit History
        self.history_view = HistoryView(self.notebook, self.db)
        self.notebook.add(self.history_view, text="  Verification Audit History  ")

        # Tab 4: Avalanche Effect & CNS Concepts Lab
        self.avalanche_view = AvalancheView(self.notebook)
        self.notebook.add(self.avalanche_view, text="  Avalanche Effect Lab  ")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, event) -> None:
        selected_tab = self.notebook.tab(self.notebook.select(), "text")
        if "Audit History" in selected_tab:
            self.history_view.refresh_history()
        elif "Baseline Files" in selected_tab:
            self._load_registered_files_table()
        self.refresh_stats()

    # =========================================================================
    # Tab 1: Verification & Quick Actions
    # =========================================================================

    def _build_verify_tab(self, parent: tk.Widget) -> None:
        container = tk.Frame(parent, bg=COLOR_BG_DARK, padx=8, pady=12)
        container.pack(fill="both", expand=True)

        # Top Action Split: Register File (Left) vs Verify File (Right)
        split_frame = tk.Frame(container, bg=COLOR_BG_DARK)
        split_frame.pack(fill="x", pady=(0, 10))

        split_frame.columnconfigure(0, weight=1)
        split_frame.columnconfigure(1, weight=1)

        # --- LEFT PANEL: REGISTER A NEW FILE BASELINE ---
        panel_reg = tk.Frame(split_frame, bg=COLOR_CARD_BG, padx=16, pady=14)
        panel_reg.grid(row=0, column=0, padx=(0, 8), sticky="nsew")

        tk.Label(panel_reg, text="1. Register File Baseline", font=FONT_HEADING, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(anchor="w")
        tk.Label(
            panel_reg,
            text="Calculate initial SHA-256 digest and record in trusted database.",
            font=FONT_SUBTITLE,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD_BG
        ).pack(anchor="w", pady=(2, 8))

        reg_row = tk.Frame(panel_reg, bg=COLOR_CARD_BG)
        reg_row.pack(fill="x", pady=4)

        self.reg_path_var = tk.StringVar()
        self.reg_entry = tk.Entry(
            reg_row,
            textvariable=self.reg_path_var,
            font=FONT_BODY,
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_WHITE,
            insertbackground=COLOR_TEXT_WHITE,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1
        )
        self.reg_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_browse_reg = ttk.Button(reg_row, text="Browse...", style="Secondary.TButton", command=self._browse_reg_file)
        btn_browse_reg.pack(side="right")

        btn_reg = ttk.Button(panel_reg, text="Calculate & Register Baseline", style="Primary.TButton", command=self._on_register_click)
        btn_reg.pack(anchor="w", pady=(10, 0))

        # --- RIGHT PANEL: VERIFY FILE INTEGRITY ---
        panel_ver = tk.Frame(split_frame, bg=COLOR_CARD_BG, padx=16, pady=14)
        panel_ver.grid(row=0, column=1, padx=(8, 0), sticky="nsew")

        tk.Label(panel_ver, text="2. Verify File Integrity", font=FONT_HEADING, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(anchor="w")
        tk.Label(
            panel_ver,
            text="Re-compute SHA-256 and detect any tampering or bit modification.",
            font=FONT_SUBTITLE,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD_BG
        ).pack(anchor="w", pady=(2, 8))

        ver_row = tk.Frame(panel_ver, bg=COLOR_CARD_BG)
        ver_row.pack(fill="x", pady=4)

        self.ver_path_var = tk.StringVar()
        self.ver_entry = tk.Entry(
            ver_row,
            textvariable=self.ver_path_var,
            font=FONT_BODY,
            bg=COLOR_INPUT_BG,
            fg=COLOR_TEXT_WHITE,
            insertbackground=COLOR_TEXT_WHITE,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1
        )
        self.ver_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_browse_ver = ttk.Button(ver_row, text="Browse...", style="Secondary.TButton", command=self._browse_ver_file)
        btn_browse_ver.pack(side="right")

        btn_verify = ttk.Button(panel_ver, text="Verify File Integrity", style="Success.TButton", command=self._on_verify_click)
        btn_verify.pack(anchor="w", pady=(10, 0))

        # --- LIVE RESULTS INSPECTION CARD ---
        self.result_card = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=14)
        self.result_card.pack(fill="both", expand=True, pady=6)

        res_header = tk.Frame(self.result_card, bg=COLOR_CARD_BG)
        res_header.pack(fill="x")

        tk.Label(res_header, text="Verification Analysis & Hash Comparison", font=FONT_HEADING, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(side="left")

        self.lbl_status_badge = tk.Label(
            res_header,
            text="AWAITING VERIFICATION",
            font=FONT_BODY_BOLD,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_INPUT_BG,
            padx=12,
            pady=4
        )
        self.lbl_status_badge.pack(side="right")

        # Result Details Grid
        details_grid = tk.Frame(self.result_card, bg=COLOR_CARD_BG)
        details_grid.pack(fill="x", pady=(12, 4))

        # File target
        tk.Label(details_grid, text="File Name:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG, width=14, anchor="w").grid(row=0, column=0, sticky="w", pady=2)
        self.lbl_res_fname = tk.Label(details_grid, text="None selected", font=FONT_BODY, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG)
        self.lbl_res_fname.grid(row=0, column=1, sticky="w", pady=2)

        tk.Label(details_grid, text="Full Path:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG, width=14, anchor="w").grid(row=1, column=0, sticky="w", pady=2)
        self.lbl_res_path = tk.Label(details_grid, text="—", font=FONT_BODY, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG)
        self.lbl_res_path.grid(row=1, column=1, sticky="w", pady=2)

        # Expected Hash Row
        tk.Label(self.result_card, text="Expected (Registered Baseline) SHA-256:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(8, 2))
        self.row_exp, self.entry_exp_hash = self._create_hash_display_row(self.result_card)

        # Actual Hash Row
        tk.Label(self.result_card, text="Actual (Current Computed) SHA-256:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(8, 2))
        self.row_act, self.entry_act_hash = self._create_hash_display_row(self.result_card)

        # Footer Actions on Results
        self.res_actions_bar = tk.Frame(self.result_card, bg=COLOR_CARD_BG)
        self.res_actions_bar.pack(fill="x", pady=(14, 0))

        self.btn_save_report = ttk.Button(
            self.res_actions_bar,
            text="Generate Text Report",
            style="Primary.TButton",
            command=self._on_save_report_click,
            state="disabled"
        )
        self.btn_save_report.pack(side="left", padx=4)

        self.lbl_avalanche_note = tk.Label(
            self.res_actions_bar,
            text="",
            font=FONT_BODY_BOLD,
            fg=COLOR_DANGER,
            bg=COLOR_CARD_BG
        )
        self.lbl_avalanche_note.pack(side="left", padx=12)

    def _create_hash_display_row(self, parent: tk.Widget):
        row = tk.Frame(parent, bg=COLOR_INPUT_BG, padx=8, pady=4, highlightbackground=COLOR_BORDER, highlightthickness=1)
        row.pack(fill="x", pady=2)

        entry = tk.Entry(row, font=FONT_HASH, fg=COLOR_TEXT_WHITE, bg=COLOR_INPUT_BG, bd=0, relief="flat")
        entry.insert(0, "—")
        entry.configure(state="readonly")
        entry.pack(side="left", fill="x", expand=True)

        btn_copy = ttk.Button(row, text="Copy", style="Secondary.TButton", command=lambda: self._copy_text(entry.get()))
        btn_copy.pack(side="right", padx=(4, 0))

        return row, entry

    def _copy_text(self, text: str) -> None:
        if not text or text == "—":
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Hash copied to clipboard!", parent=self)

    def _browse_reg_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Select File to Register Baseline")
        if path:
            self.reg_path_var.set(path)
            # Pre-fill verify entry as well for user convenience
            if not self.ver_path_var.get():
                self.ver_path_var.set(path)

    def _browse_ver_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Select File to Verify Integrity")
        if path:
            self.ver_path_var.set(path)

    def _on_register_click(self) -> None:
        path_str = self.reg_path_var.get().strip()
        if not path_str:
            messagebox.showwarning("Input Required", "Please select a file to register.", parent=self)
            return

        path = Path(path_str).resolve()
        if not path.exists():
            messagebox.showerror("Error", f"File not found:\n{path}", parent=self)
            return

        # Attempt registration (without overwrite first)
        success, msg, record = self.service.register_file(path, allow_overwrite=False)

        if success:
            messagebox.showinfo("Registration Successful", msg, parent=self)
            self.refresh_all_data()
            self.ver_path_var.set(str(path))
        else:
            # Check if file was already registered and requires overwrite warning
            existing = self.db.get_file_by_path(path)
            if existing:
                try:
                    new_hash = calculate_file_sha256(path)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not read file: {e}", parent=self)
                    return

                should_overwrite = show_baseline_overwrite_warning(
                    parent=self,
                    filename=path.name,
                    old_hash=existing["trusted_hash"],
                    new_hash=new_hash
                )
                if should_overwrite:
                    ok, upd_msg, upd_rec = self.service.register_file(path, allow_overwrite=True)
                    if ok:
                        messagebox.showinfo("Baseline Updated", upd_msg, parent=self)
                        self.refresh_all_data()
                    else:
                        messagebox.showerror("Update Error", upd_msg, parent=self)
            else:
                messagebox.showerror("Registration Error", msg, parent=self)

    def _on_verify_click(self) -> None:
        path_str = self.ver_path_var.get().strip()
        if not path_str:
            messagebox.showwarning("Input Required", "Please select a file to verify.", parent=self)
            return

        res = self.service.verify_file(path_str)
        self.last_result = res
        self._display_verification_result(res)
        self.refresh_stats()

    def _display_verification_result(self, res: VerificationResult) -> None:
        self.lbl_res_fname.config(text=res.filename)
        self.lbl_res_path.config(text=res.file_path)

        # Expected hash
        self.entry_exp_hash.configure(state="normal")
        self.entry_exp_hash.delete(0, tk.END)
        self.entry_exp_hash.insert(0, res.expected_hash or "None (File not registered)")
        self.entry_exp_hash.configure(state="readonly")

        # Actual hash
        self.entry_act_hash.configure(state="normal")
        self.entry_act_hash.delete(0, tk.END)
        self.entry_act_hash.insert(0, res.actual_hash or "None (File missing or unreadable)")
        self.entry_act_hash.configure(state="readonly")

        # Update Badge Color
        if res.status == STATUS_VERIFIED:
            self.lbl_status_badge.config(
                text="✓ INTEGRITY VERIFIED (CLEAN)",
                fg=COLOR_SUCCESS,
                bg=COLOR_SUCCESS_BG
            )
            self.lbl_avalanche_note.config(text="Digest matches trusted baseline exactly.", fg=COLOR_SUCCESS)
        elif res.status == STATUS_MODIFIED:
            self.lbl_status_badge.config(
                text="✕ FILE MODIFIED — HASH MISMATCH",
                fg=COLOR_DANGER,
                bg=COLOR_DANGER_BG
            )
            if res.differing_bits:
                pct = round((res.differing_bits / 256.0) * 100, 1)
                self.lbl_avalanche_note.config(
                    text=f"TAMPERING DETECTED: {res.differing_bits}/256 bits changed ({pct}%)",
                    fg=COLOR_DANGER
                )
            else:
                self.lbl_avalanche_note.config(text="TAMPERING DETECTED: Content has changed!", fg=COLOR_DANGER)
        elif res.status == STATUS_NOT_REGISTERED:
            self.lbl_status_badge.config(
                text="! FILE NOT REGISTERED",
                fg=COLOR_WARNING,
                bg=COLOR_WARNING_BG
            )
            self.lbl_avalanche_note.config(text="No baseline found. Register file first.", fg=COLOR_WARNING)
        elif res.status == STATUS_NOT_FOUND:
            self.lbl_status_badge.config(
                text="! FILE NOT FOUND ON DISK",
                fg=COLOR_WARNING,
                bg=COLOR_WARNING_BG
            )
            self.lbl_avalanche_note.config(text="Registered file is missing or was deleted.", fg=COLOR_WARNING)
        else:
            self.lbl_status_badge.config(
                text=f"! {res.status}",
                fg=COLOR_WARNING,
                bg=COLOR_WARNING_BG
            )
            self.lbl_avalanche_note.config(text=res.error_message or "Verification error", fg=COLOR_WARNING)

        self.btn_save_report.config(state="normal")

    def _on_save_report_click(self) -> None:
        if not self.last_result:
            return
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.last_result.filename)
        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Save Verification Report",
            initialfile=f"integrity_report_{safe_name}.txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")]
        )
        if dest:
            try:
                generate_text_report(self.last_result, dest)
                messagebox.showinfo("Report Saved", f"Verification report saved to:\n{dest}", parent=self)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}", parent=self)

    # =========================================================================
    # Tab 2: Registered Baselines Management
    # =========================================================================

    def _build_baselines_tab(self, parent: tk.Widget) -> None:
        container = tk.Frame(parent, bg=COLOR_BG_DARK, padx=12, pady=12)
        container.pack(fill="both", expand=True)

        # Action Buttons Toolbar
        toolbar = tk.Frame(container, bg=COLOR_CARD_BG, padx=14, pady=10)
        toolbar.pack(fill="x", pady=(0, 8))

        btn_verify_sel = ttk.Button(toolbar, text="Verify Selected File", style="Success.TButton", command=self._verify_selected_baseline)
        btn_verify_sel.pack(side="left", padx=4)

        btn_update_sel = ttk.Button(toolbar, text="Update Baseline (Re-register)", style="Danger.TButton", command=self._update_selected_baseline)
        btn_update_sel.pack(side="left", padx=4)

        btn_del_sel = ttk.Button(toolbar, text="Delete Baseline", style="Secondary.TButton", command=self._delete_selected_baseline)
        btn_del_sel.pack(side="left", padx=4)

        btn_refresh_tbl = ttk.Button(toolbar, text="Refresh Table", style="Secondary.TButton", command=self._load_registered_files_table)
        btn_refresh_tbl.pack(side="right", padx=4)

        # Baselines Treeview
        tbl_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=8, pady=8)
        tbl_frame.pack(fill="both", expand=True)

        cols = ("id", "filename", "path", "trusted_hash", "size", "registered_on", "last_status")
        self.tree_baselines = ttk.Treeview(
            tbl_frame,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=14
        )

        self.tree_baselines.heading("id", text="ID")
        self.tree_baselines.heading("filename", text="File Name")
        self.tree_baselines.heading("path", text="Absolute Path")
        self.tree_baselines.heading("trusted_hash", text="Trusted SHA-256 Digest")
        self.tree_baselines.heading("size", text="Size (Bytes)")
        self.tree_baselines.heading("registered_on", text="Registered On")
        self.tree_baselines.heading("last_status", text="Last Verification")

        self.tree_baselines.column("id", width=40, anchor="center")
        self.tree_baselines.column("filename", width=140, anchor="w")
        self.tree_baselines.column("path", width=220, anchor="w")
        self.tree_baselines.column("trusted_hash", width=190, anchor="w")
        self.tree_baselines.column("size", width=80, anchor="e")
        self.tree_baselines.column("registered_on", width=140, anchor="center")
        self.tree_baselines.column("last_status", width=180, anchor="center")

        self.tree_baselines.tag_configure("VERIFIED", foreground=COLOR_SUCCESS)
        self.tree_baselines.tag_configure("MODIFIED", foreground=COLOR_DANGER)
        self.tree_baselines.tag_configure("PENDING", foreground=COLOR_TEXT_MUTED)

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree_baselines.yview, style="Vertical.TScrollbar")
        self.tree_baselines.configure(yscrollcommand=vsb.set)

        self.tree_baselines.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _load_registered_files_table(self) -> None:
        for item in self.tree_baselines.get_children():
            self.tree_baselines.delete(item)

        files = self.db.get_all_files()
        for f in files:
            status = f.get("last_verification_status") or "PENDING"
            tag = "PENDING"
            if status == STATUS_VERIFIED:
                tag = "VERIFIED"
            elif status == STATUS_MODIFIED:
                tag = "MODIFIED"

            hash_preview = f["trusted_hash"][:18] + "..."

            self.tree_baselines.insert(
                "",
                "end",
                iid=str(f["id"]),
                values=(
                    f["id"],
                    f["filename"],
                    f["absolute_path"],
                    hash_preview,
                    f"{f['file_size']:,}",
                    f["registration_timestamp"],
                    status
                ),
                tags=(tag,)
            )

    def _get_selected_baseline_id(self) -> Optional[int]:
        sel = self.tree_baselines.selection()
        if not sel:
            messagebox.showinfo("Select Row", "Please select a file record from the table first.", parent=self)
            return None
        return int(sel[0])

    def _verify_selected_baseline(self) -> None:
        file_id = self._get_selected_baseline_id()
        if not file_id:
            return

        rec = self.db.get_file_by_id(file_id)
        if not rec:
            return

        res = self.service.verify_file(rec["absolute_path"])
        self.last_result = res
        self._load_registered_files_table()
        self.refresh_stats()

        # Show modal dialog with result
        VerificationResultDialog(self, res)

    def _update_selected_baseline(self) -> None:
        file_id = self._get_selected_baseline_id()
        if not file_id:
            return

        rec = self.db.get_file_by_id(file_id)
        if not rec:
            return

        path = Path(rec["absolute_path"])
        if not path.exists():
            messagebox.showerror("Error", f"File does not exist on disk:\n{path}", parent=self)
            return

        try:
            new_hash = calculate_file_sha256(path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute SHA-256: {e}", parent=self)
            return

        confirmed = show_baseline_overwrite_warning(
            parent=self,
            filename=path.name,
            old_hash=rec["trusted_hash"],
            new_hash=new_hash
        )
        if confirmed:
            ok, msg, _ = self.service.register_file(path, allow_overwrite=True)
            if ok:
                messagebox.showinfo("Updated", msg, parent=self)
                self._load_registered_files_table()
                self.refresh_stats()
            else:
                messagebox.showerror("Error", msg, parent=self)

    def _delete_selected_baseline(self) -> None:
        file_id = self._get_selected_baseline_id()
        if not file_id:
            return

        rec = self.db.get_file_by_id(file_id)
        if not rec:
            return

        conf = messagebox.askyesno(
            "Delete Baseline",
            f"Are you sure you want to remove the trusted baseline for '{rec['filename']}'?\n"
            "This will not delete the file from disk, but future verifications will report it as unregistered.",
            parent=self,
            icon="warning"
        )
        if conf:
            self.service.delete_baseline(file_id)
            self._load_registered_files_table()
            self.refresh_stats()
            messagebox.showinfo("Deleted", f"Baseline for '{rec['filename']}' removed.", parent=self)

    def _on_verify_all_registered(self) -> None:
        files = self.db.get_all_files()
        if not files:
            messagebox.showinfo("Verify All", "No baseline files are currently registered.", parent=self)
            return

        results = self.service.verify_all_registered()
        self.refresh_all_data()

        clean_count = sum(1 for r in results if r.status == STATUS_VERIFIED)
        tamper_count = sum(1 for r in results if r.status == STATUS_MODIFIED)
        other_count = len(results) - clean_count - tamper_count

        summary_msg = (
            f"Batch Verification Complete!\n\n"
            f"Total Files Inspected : {len(results)}\n"
            f"Integrity Verified (Clean): {clean_count}\n"
            f"Tampering / Mismatched: {tamper_count}\n"
            f"Missing / Errors       : {other_count}\n\n"
            "Would you like to export the batch report?"
        )
        should_export = messagebox.askyesno("Batch Verification Complete", summary_msg, parent=self)
        if should_export:
            dest = filedialog.asksaveasfilename(
                parent=self,
                title="Save Batch Verification Report",
                initialfile="batch_verification_report.txt",
                filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")]
            )
            if dest:
                try:
                    generate_batch_summary_report(results, dest)
                    messagebox.showinfo("Exported", f"Batch report saved to:\n{dest}", parent=self)
                except Exception as e:
                    messagebox.showerror("Export Failed", f"Could not save batch report: {e}", parent=self)

    # =========================================================================
    # Data Refresh
    # =========================================================================

    def refresh_stats(self) -> None:
        stats = self.db.get_statistics()
        self.lbl_count_registered.config(text=str(stats["total_registered"]))
        self.lbl_count_verified.config(text=str(stats["verified_success"]))
        self.lbl_count_tampered.config(text=str(stats["tampering_detected"]))
        self.lbl_count_total.config(text=str(stats["total_verifications"]))

    def refresh_all_data(self) -> None:
        self.refresh_stats()
        self._load_registered_files_table()
        if hasattr(self, "history_view"):
            self.history_view.refresh_history()
