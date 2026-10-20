"""
gui/avalanche_view.py - Interactive SHA-256 Avalanche Effect and Theory Lab
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Provides an educational demonstration of the Avalanche Effect in SHA-256,
showing how a single-character or single-bit modification causes ~50%
of all output digest bits to flip unpredictably.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from hashing import calculate_string_sha256, compute_avalanche_effect
from gui.styles import (
    COLOR_BG_DARK, COLOR_CARD_BG, COLOR_BORDER, COLOR_INPUT_BG,
    COLOR_TEXT_WHITE, COLOR_TEXT_MUTED, COLOR_PRIMARY, COLOR_SUCCESS,
    COLOR_DANGER, FONT_HEADING, FONT_BODY, FONT_BODY_BOLD, FONT_HASH,
    FONT_STAT_NUMBER, FONT_SUBTITLE
)


class AvalancheView(tk.Frame):
    """Interactive educational panel for exploring SHA-256 properties."""

    def __init__(self, parent: tk.Widget):
        super().__init__(parent, bg=COLOR_BG_DARK)
        self._build_ui()
        self._load_sample_1()

    def _build_ui(self) -> None:
        scrollable_container = tk.Frame(self, bg=COLOR_BG_DARK)
        scrollable_container.pack(fill="both", expand=True, padx=16, pady=12)

        # Header intro
        intro_card = tk.Frame(scrollable_container, bg=COLOR_CARD_BG, padx=16, pady=12)
        intro_card.pack(fill="x", pady=(0, 10))

        tk.Label(
            intro_card,
            text="Cryptographic Concept Lab: The Avalanche Effect in SHA-256",
            font=FONT_HEADING,
            fg=COLOR_TEXT_WHITE,
            bg=COLOR_CARD_BG
        ).pack(anchor="w")

        intro_text = (
            "The Avalanche Effect is a vital property of cryptographic hash functions and block ciphers.\n"
            "A minor change in input (even flipping 1 bit) causes a drastic, pseudo-random change in output digest,\n"
            "statistically flipping approximately 50% of the 256 bits (Strict Avalanche Criterion)."
        )
        tk.Label(
            intro_card,
            text=intro_text,
            font=FONT_SUBTITLE,
            fg=COLOR_TEXT_MUTED,
            bg=COLOR_CARD_BG,
            justify="left"
        ).pack(anchor="w", pady=(4, 0))

        # Input cards comparison
        inputs_frame = tk.Frame(scrollable_container, bg=COLOR_BG_DARK)
        inputs_frame.pack(fill="x", pady=6)

        # Left: Input 1
        card1 = tk.Frame(inputs_frame, bg=COLOR_CARD_BG, padx=12, pady=10)
        card1.pack(side="left", fill="both", expand=True, padx=(0, 6))

        tk.Label(card1, text="Input String A:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(anchor="w")
        self.entry_a = tk.Entry(card1, font=FONT_BODY, bg=COLOR_INPUT_BG, fg=COLOR_TEXT_WHITE, insertbackground=COLOR_TEXT_WHITE, highlightbackground=COLOR_BORDER, highlightthickness=1)
        self.entry_a.pack(fill="x", pady=4)
        self.entry_a.bind("<KeyRelease>", lambda e: self.calculate_avalanche())

        tk.Label(card1, text="SHA-256 Digest A (256 bits):", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(4, 0))
        self.lbl_hash_a = tk.Text(card1, height=2, font=FONT_HASH, bg=COLOR_INPUT_BG, fg=COLOR_TEXT_WHITE, relief="flat", highlightbackground=COLOR_BORDER, highlightthickness=1)
        self.lbl_hash_a.pack(fill="x", pady=2)

        # Right: Input 2
        card2 = tk.Frame(inputs_frame, bg=COLOR_CARD_BG, padx=12, pady=10)
        card2.pack(side="right", fill="both", expand=True, padx=(6, 0))

        tk.Label(card2, text="Input String B (Modified):", font=FONT_BODY_BOLD, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(anchor="w")
        self.entry_b = tk.Entry(card2, font=FONT_BODY, bg=COLOR_INPUT_BG, fg=COLOR_TEXT_WHITE, insertbackground=COLOR_TEXT_WHITE, highlightbackground=COLOR_BORDER, highlightthickness=1)
        self.entry_b.pack(fill="x", pady=4)
        self.entry_b.bind("<KeyRelease>", lambda e: self.calculate_avalanche())

        tk.Label(card2, text="SHA-256 Digest B (256 bits):", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack(anchor="w", pady=(4, 0))
        self.lbl_hash_b = tk.Text(card2, height=2, font=FONT_HASH, bg=COLOR_INPUT_BG, fg=COLOR_TEXT_WHITE, relief="flat", highlightbackground=COLOR_BORDER, highlightthickness=1)
        self.lbl_hash_b.pack(fill="x", pady=2)

        # Quick Demo Buttons Bar
        btn_bar = tk.Frame(scrollable_container, bg=COLOR_BG_DARK)
        btn_bar.pack(fill="x", pady=6)

        tk.Label(btn_bar, text="Preset Tests:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_BG_DARK).pack(side="left", padx=(0, 8))
        ttk.Button(btn_bar, text="Case Change (P vs p)", style="Secondary.TButton", command=self._load_sample_1).pack(side="left", padx=4)
        ttk.Button(btn_bar, text="1-Letter Typo ('secure' vs 'secure!')", style="Secondary.TButton", command=self._load_sample_2).pack(side="left", padx=4)
        ttk.Button(btn_bar, text="Appended Period", style="Secondary.TButton", command=self._load_sample_3).pack(side="left", padx=4)

        # Stats Result Card
        self.stats_card = tk.Frame(scrollable_container, bg=COLOR_CARD_BG, padx=16, pady=12)
        self.stats_card.pack(fill="x", pady=8)

        stats_inner = tk.Frame(self.stats_card, bg=COLOR_CARD_BG)
        stats_inner.pack(fill="x")

        # Metric 1: Bits changed
        box1 = tk.Frame(stats_inner, bg=COLOR_CARD_BG)
        box1.pack(side="left", expand=True)
        self.lbl_diff_bits = tk.Label(box1, text="0 / 256", font=FONT_STAT_NUMBER, fg=COLOR_PRIMARY, bg=COLOR_CARD_BG)
        self.lbl_diff_bits.pack()
        tk.Label(box1, text="Differing Digest Bits", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack()

        # Metric 2: Percentage change
        box2 = tk.Frame(stats_inner, bg=COLOR_CARD_BG)
        box2.pack(side="left", expand=True)
        self.lbl_pct = tk.Label(box2, text="0.0%", font=FONT_STAT_NUMBER, fg=COLOR_SUCCESS, bg=COLOR_CARD_BG)
        self.lbl_pct.pack()
        tk.Label(box2, text="Percentage Change (Target ~50%)", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack()

        # Metric 3: Hamming Distance Evaluation
        box3 = tk.Frame(stats_inner, bg=COLOR_CARD_BG)
        box3.pack(side="left", expand=True)
        self.lbl_eval = tk.Label(box3, text="EVALUATING", font=FONT_STAT_NUMBER, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG)
        self.lbl_eval.pack()
        tk.Label(box3, text="Avalanche Strength", font=FONT_BODY_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG).pack()

        # Theory reference box
        theory_card = tk.Frame(scrollable_container, bg=COLOR_CARD_BG, padx=16, pady=12)
        theory_card.pack(fill="x", pady=6)

        tk.Label(theory_card, text="Core CNS Theory Summary:", font=FONT_BODY_BOLD, fg=COLOR_TEXT_WHITE, bg=COLOR_CARD_BG).pack(anchor="w")

        bullets = (
            "• Hashing vs Encryption: Hashing is a one-way mathematical function (no key can reverse the digest).\n"
            "  Encryption is a two-way reversible transformation requiring a secret key.\n"
            "• Pre-Image Resistance: Given hash H, it is computationally infeasible to find message M such that H = hash(M).\n"
            "• Second Pre-Image Resistance: Given M1, it is infeasible to find M2 (where M1 != M2) such that hash(M1) = hash(M2).\n"
            "• Collision Resistance: It is infeasible to find ANY pair of distinct messages M1, M2 such that hash(M1) = hash(M2)."
        )
        tk.Label(theory_card, text=bullets, font=FONT_SUBTITLE, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD_BG, justify="left").pack(anchor="w", pady=(4, 0))

    def _load_sample_1(self) -> None:
        self.entry_a.delete(0, tk.END)
        self.entry_a.insert(0, "Cryptography and Network Security")
        self.entry_b.delete(0, tk.END)
        self.entry_b.insert(0, "cryptography and Network Security")
        self.calculate_avalanche()

    def _load_sample_2(self) -> None:
        self.entry_a.delete(0, tk.END)
        self.entry_a.insert(0, "Original secure content")
        self.entry_b.delete(0, tk.END)
        self.entry_b.insert(0, "Modified secure content")
        self.calculate_avalanche()

    def _load_sample_3(self) -> None:
        self.entry_a.delete(0, tk.END)
        self.entry_a.insert(0, "Integrity Baseline Verification")
        self.entry_b.delete(0, tk.END)
        self.entry_b.insert(0, "Integrity Baseline Verification.")
        self.calculate_avalanche()

    def calculate_avalanche(self) -> None:
        text_a = self.entry_a.get()
        text_b = self.entry_b.get()

        res = compute_avalanche_effect(text_a, text_b)

        # Update text displays
        self.lbl_hash_a.configure(state="normal")
        self.lbl_hash_a.delete("1.0", tk.END)
        self.lbl_hash_a.insert("1.0", res["hash1"])
        self.lbl_hash_a.configure(state="disabled")

        self.lbl_hash_b.configure(state="normal")
        self.lbl_hash_b.delete("1.0", tk.END)
        self.lbl_hash_b.insert("1.0", res["hash2"])
        self.lbl_hash_b.configure(state="disabled")

        diff = res["differing_bits"]
        pct = res["percentage_difference"]

        self.lbl_diff_bits.config(text=f"{diff} / 256")
        self.lbl_pct.config(text=f"{pct}%")

        if diff == 0:
            self.lbl_eval.config(text="IDENTICAL", fg=COLOR_TEXT_MUTED)
        elif 40.0 <= pct <= 60.0:
            self.lbl_eval.config(text="EXCELLENT", fg=COLOR_SUCCESS)
        else:
            self.lbl_eval.config(text="STRONG", fg=COLOR_PRIMARY)
