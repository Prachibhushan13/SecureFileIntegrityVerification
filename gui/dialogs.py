"""
gui/dialogs.py - Custom Dialogs and Result Modals
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Provides dialog windows for:
- Baseline overwrite warnings and confirmations
- Verification result displays with side-by-side hash comparison
- Copy-to-clipboard functionality
- Error alerts
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Callable
from pathlib import Path

from gui.styles import (
    COLOR_BG_DARK, COLOR_CARD_BG, COLOR_BORDER, COLOR_INPUT_BG,
    COLOR_TEXT_WHITE, COLOR_TEXT_MUTED, COLOR_PRIMARY, COLOR_SUCCESS,
    COLOR_DANGER, COLOR_WARNING, COLOR_SUCCESS_BG, COLOR_DANGER_BG,
    COLOR_WARNING_BG, FONT_TITLE, FONT_HEADING, FONT_BODY, FONT_BODY_BOLD,
    FONT_HASH, FONT_HASH_BOLD, FONT_SUBTITLE
)
from integrity_service import (
    VerificationResult, STATUS_VERIFIED, STATUS_MODIFIED,
    STATUS_NOT_REGISTERED, STATUS_NOT_FOUND, STATUS_ERROR
)
from report_generator import generate_text_report


class VerificationResultDialog(tk.Toplevel):
    """
    Modal window presenting the full results of a file integrity verification,
    including side-by-side hash comparison, status indicators, and report export.
    """

    def __init__(self, parent: tk.Tk | tk.Toplevel, result: VerificationResult):
        super().__init__(parent)
        self.result = result
        self.title(f"Verification Result - {result.filename}")
        self.geometry("720x580")
        self.minsize(680, 520)
        self.configure(bg=COLOR_BG_DARK)
        self.transient(parent)
        self.grab_set()

        self._build_ui()
        self._center_window()

    def _center_window(self) -> None:
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self) -> None:
        # Status Banner Color
        status = self.result.status
        if status == STATUS_VERIFIED:
            banner_bg = COLOR_SUCCESS_BG
            banner_fg = COLOR_SUCCESS
            icon = "✓"
        elif status == STATUS_MODIFIED:
            banner_bg = COLOR_DANGER_BG
            banner_fg = COLOR_DANGER
            icon = "✕"
        else:
            banner_bg = COLOR_WARNING_BG
            banner_fg = COLOR_WARNING
            icon = "!"

        # Top Banner
        banner = tk.Frame(self, bg=banner_bg, padx=20, pady=16)
        banner.pack(fill="x", padx=16, pady=(16, 8))

        lbl_icon = tk.Label(banner, text=icon, font=("Helvetica", 24, "bold"), fg=banner_fg, bg=banner_bg)
        lbl_icon.pack(side="left", padx=(0, 14))

        info_box = tk.Frame(banner, bg=banner_bg)
        info_box.pack(side="left", fill="both", expand=True)

        lbl_status = tk.Label(info_box, text=status, font=FONT_HEADING, fg=banner_fg, bg=banner_bg)
        lbl_status.pack(anchor="w")

        lbl_file = tk.Label(
            info_box,
            text=f"File: {self.result.filename} ({f'{self.result.file_size:,} bytes' if self.result.file_size else 'Size Unknown'})",
            font=FONT_SUBTITLE,
            fg=COLOR_TEXT_WHITE,
            bg=banner_bg
        )
        lbl_file.pack(anchor="w", pady=(2, 0))

        # Main details card
        card = tk.Frame(self, bg=COLOR_CARD_BG, padx=20, pady=16, relief="flat")
        card.pack(fill="both", expand=True, padx=16, pady=8)

        # File path
        self._add_detail_row(card, "Full Path:", self.result.file_path, mono=False)
        self._add_detail_row(card, "Timestamp:", self.result.verification_timestamp, mono=False)

        # Expected Hash
        tk.Label(card, text="Expected (Trusted Baseline) SHA-256:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(8, 2))
        self._build_hash_row(card, self.result.expected_hash or "N/A (Not registered)", is_expected=True)

        # Actual Hash
        tk.Label(card, text="Actual (Current Computed) SHA-256:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(8, 2))
        self._build_hash_row(card, self.result.actual_hash or "N/A (File missing or unreadable)", is_expected=False)

        # Avalanche / Bit differences if modified
        if self.result.differing_bits is not None and self.result.differing_bits > 0:
            pct = round((self.result.differing_bits / 256.0) * 100, 2)
            lbl_avalanche = tk.Label(
                card,
                text=f"Avalanche Effect: {self.result.differing_bits} of 256 bits changed ({pct}%)",
                font=FONT_BODY_BOLD,
                fg=COLOR_DANGER,
                bg=COLOR_CARD_BG
            )
            lbl_avalanche.pack(anchor="w", pady=(6, 0))

        # Security disclaimer note
        lbl_note = tk.Label(
            card,
            text="Notice: Integrity verification proves file contents match the baseline; it does not scan for malware.",
            font=("Helvetica", 9, "italic"),
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD_BG,
            wraplength=640,
            justify="left"
        )
        lbl_note.pack(anchor="w", pady=(12, 0))

        # Bottom Button Bar
        btn_bar = tk.Frame(self, bg=COLOR_BG_DARK, pady=12)
        btn_bar.pack(fill="x", padx=16)

        btn_report = ttk.Button(btn_bar, text="Save Text Report", style="Primary.TButton", command=self._save_report)
        btn_report.pack(side="left", padx=4)

        btn_close = ttk.Button(btn_bar, text="Close", style="Secondary.TButton", command=self.destroy)
        btn_close.pack(side="right", padx=4)

    def _add_detail_row(self, parent: tk.Widget, label: str, value: str, mono: bool = False) -> None:
        row = tk.Frame(parent, bg=COLOR_CARD_BG)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=f"{label:<12}", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG, width=12, anchor="w").pack(side="left")
        tk.Label(row, text=value, font=FONT_HASH if mono else FONT_BODY, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG, anchor="w").pack(side="left", fill="x", expand=True)

    def _build_hash_row(self, parent: tk.Widget, hash_val: str, is_expected: bool) -> None:
        frame = tk.Frame(parent, bg=COLOR_INPUT_BG, padx=8, pady=6, highlightbackground=COLOR_BORDER, highlightthickness=1)
        frame.pack(fill="x", pady=(0, 4))

        color = COLOR_SUCCESS if (self.result.hash_match and hash_val != "N/A") else COLOR_TEXT_WHITE
        if not self.result.hash_match and not is_expected and hash_val not in ("N/A", "None"):
            color = COLOR_DANGER

        entry = tk.Entry(frame, font=FONT_HASH, fg=color, bg=COLOR_INPUT_BG, bd=0, relief="flat")
        entry.insert(0, hash_val)
        entry.configure(state="readonly")
        entry.pack(side="left", fill="x", expand=True)

        if hash_val not in ("N/A (Not registered)", "N/A (File missing or unreadable)"):
            btn_copy = ttk.Button(
                frame,
                text="Copy",
                style="Secondary.TButton",
                command=lambda: self._copy_to_clipboard(hash_val)
            )
            btn_copy.pack(side="right", padx=(6, 0))

    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard!", parent=self)

    def _save_report(self) -> None:
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.result.filename)
        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Save Verification Report",
            initialfile=f"integrity_report_{safe_name}.txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")]
        )
        if dest:
            try:
                generate_text_report(self.result, dest)
                messagebox.showinfo("Saved", f"Report saved successfully to:\n{dest}", parent=self)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}", parent=self)


def show_baseline_overwrite_warning(
    parent: tk.Widget,
    filename: str,
    old_hash: str,
    new_hash: str
) -> bool:
    """
    Prompts the user with an explicit cybersecurity warning before
    replacing an existing trusted baseline.
    """
    dialog = tk.Toplevel(parent)
    dialog.title("Warning: Baseline Replacement")
    dialog.geometry("620x360")
    dialog.resizable(False, False)
    dialog.configure(bg=COLOR_BG_DARK)
    dialog.transient(parent)
    dialog.grab_set()

    user_confirmed = {"value": False}

    # Center dialog
    dialog.update_idletasks()
    x = max(0, (dialog.winfo_screenwidth() - 620) // 2)
    y = max(0, (dialog.winfo_screenheight() - 360) // 2)
    dialog.geometry(f"620x360+{x}+{y}")

    # Top Alert Header
    banner = tk.Frame(dialog, bg=COLOR_WARNING_BG, padx=16, pady=12)
    banner.pack(fill="x", padx=16, pady=(16, 10))

    tk.Label(banner, text="⚠️", font=("Helvetica", 20), fg=COLOR_WARNING, bg=COLOR_WARNING_BG).pack(side="left", padx=(0, 10))
    tk.Label(
        banner,
        text="EXISTING TRUSTED BASELINE DETECTED",
        font=FONT_HEADING,
        fg=COLOR_WARNING,
        bg=COLOR_WARNING_BG
    ).pack(side="left")

    card = tk.Frame(dialog, bg=COLOR_CARD_BG, padx=16, pady=12)
    card.pack(fill="both", expand=True, padx=16, pady=6)

    msg = (
        f"A trusted baseline for '{filename}' is already recorded in the database.\n\n"
        "Security Best Practice:\n"
        "You should ONLY update the baseline if this file was modified as part of an\n"
        "authorized update. Overwriting the baseline will accept all current modifications\n"
        "as the new trusted state!"
    )
    tk.Label(card, text=msg, font=FONT_BODY, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG, justify="left", wraplength=560).pack(anchor="w", pady=(0, 8))

    tk.Label(card, text=f"Previous Baseline: {old_hash[:32]}...", font=FONT_HASH, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w")
    tk.Label(card, text=f"New Baseline     : {new_hash[:32]}...", font=FONT_HASH, fg=COLOR_PRIMARY, bg=COLOR_CARD_BG).pack(anchor="w")

    # Buttons
    btn_bar = tk.Frame(dialog, bg=COLOR_BG_DARK, pady=12)
    btn_bar.pack(fill="x", padx=16)

    def on_confirm():
        user_confirmed["value"] = True
        dialog.destroy()

    btn_cancel = ttk.Button(btn_bar, text="Cancel (Keep Current Baseline)", style="Secondary.TButton", command=dialog.destroy)
    btn_cancel.pack(side="right", padx=6)

    btn_overwrite = ttk.Button(btn_bar, text="Yes, Update Baseline", style="Danger.TButton", command=on_confirm)
    btn_overwrite.pack(side="right", padx=6)

    dialog.wait_window()
    return user_confirmed["value"]
