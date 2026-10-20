"""
gui/styles.py - Visual Design System and TTK Styles
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Defines the color palette, typography tokens, and TTK widget styles
for a modern, professional cybersecurity desktop application.
"""

import tkinter as tk
from tkinter import ttk

# =============================================================================
# Color Palette (Tailored Slate & Cybersecurity Accents)
# =============================================================================
COLOR_BG_DARK = "#0f172a"        # Deep slate background
COLOR_CARD_BG = "#1e293b"        # Card / panel background
COLOR_CARD_HOVER = "#273549"     # Slightly lighter card hover
COLOR_BORDER = "#334155"         # Subtle dividing borders
COLOR_INPUT_BG = "#0b1120"       # Text entry / display field background

# Text colors
COLOR_TEXT_WHITE = "#f8fafc"     # Primary high-contrast text
COLOR_TEXT_MUTED = "#94a3b8"     # Secondary labels and subtitles
COLOR_TEXT_DIM = "#64748b"       # Footnotes and disabled states

# Action & Semantic Indicators
COLOR_PRIMARY = "#3b82f6"        # Primary blue action
COLOR_PRIMARY_HOVER = "#2563eb"
COLOR_SUCCESS = "#10b981"        # Emerald green for Verified
COLOR_SUCCESS_BG = "#064e3b"
COLOR_DANGER = "#ef4444"         # Crimson red for Mismatch / Tamper
COLOR_DANGER_BG = "#450a0a"
COLOR_WARNING = "#f59e0b"        # Amber for Unregistered / Missing
COLOR_WARNING_BG = "#451a03"
COLOR_INFO = "#06b6d4"           # Cyan info accent

# Fonts
FONT_FAMILY = "Helvetica"
FONT_MONO = "Menlo" if "Menlo" in ("Menlo", "Courier") else "Courier"

FONT_TITLE = (FONT_FAMILY, 16, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 10, "normal")
FONT_HEADING = (FONT_FAMILY, 12, "bold")
FONT_BODY = (FONT_FAMILY, 10, "normal")
FONT_BODY_BOLD = (FONT_FAMILY, 10, "bold")
FONT_STAT_NUMBER = (FONT_FAMILY, 20, "bold")
FONT_STAT_LABEL = (FONT_FAMILY, 9, "bold")
FONT_HASH = (FONT_MONO, 9, "normal")
FONT_HASH_BOLD = (FONT_MONO, 10, "bold")
FONT_BADGE = (FONT_FAMILY, 9, "bold")


def configure_app_styles(root: tk.Tk) -> None:
    """Configures modern ttk styles on the root window."""
    root.configure(bg=COLOR_BG_DARK)

    style = ttk.Style(root)
    # Using 'clam' as base engine across macOS/Linux/Windows for consistent colors
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    # Global background colors
    style.configure(".", background=COLOR_BG_DARK, foreground=COLOR_TEXT_WHITE, font=FONT_BODY)

    # Frame styles
    style.configure("TFrame", background=COLOR_BG_DARK)
    style.configure("Card.TFrame", background=COLOR_CARD_BG, relief="flat")
    style.configure("DarkInput.TFrame", background=COLOR_INPUT_BG, relief="solid", borderwidth=1)

    # Label styles
    style.configure("TLabel", background=COLOR_BG_DARK, foreground=COLOR_TEXT_WHITE, font=FONT_BODY)
    style.configure("Card.TLabel", background=COLOR_CARD_BG, foreground=COLOR_TEXT_WHITE, font=FONT_BODY)
    style.configure("CardMuted.TLabel", background=COLOR_CARD_BG, foreground=COLOR_TEXT_MUTED, font=FONT_SUBTITLE)
    style.configure("Heading.TLabel", background=COLOR_CARD_BG, foreground=COLOR_TEXT_WHITE, font=FONT_HEADING)
    style.configure("AppTitle.TLabel", background=COLOR_BG_DARK, foreground=COLOR_TEXT_WHITE, font=FONT_TITLE)
    style.configure("AppSubtitle.TLabel", background=COLOR_BG_DARK, foreground=COLOR_TEXT_MUTED, font=FONT_SUBTITLE)

    # Stat Card styles
    style.configure("StatCard.TFrame", background=COLOR_CARD_BG)
    style.configure("StatNum.TLabel", background=COLOR_CARD_BG, foreground=COLOR_TEXT_WHITE, font=FONT_STAT_NUMBER)
    style.configure("StatLabel.TLabel", background=COLOR_CARD_BG, foreground=COLOR_TEXT_MUTED, font=FONT_STAT_LABEL)

    # Buttons
    style.configure(
        "Primary.TButton",
        background=COLOR_PRIMARY,
        foreground=COLOR_TEXT_WHITE,
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(12, 7)
    )
    style.map(
        "Primary.TButton",
        background=[("active", COLOR_PRIMARY_HOVER), ("disabled", COLOR_BORDER)]
    )

    style.configure(
        "Success.TButton",
        background=COLOR_SUCCESS,
        foreground=COLOR_TEXT_WHITE,
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(12, 7)
    )
    style.map(
        "Success.TButton",
        background=[("active", "#059669"), ("disabled", COLOR_BORDER)]
    )

    style.configure(
        "Secondary.TButton",
        background=COLOR_BORDER,
        foreground=COLOR_TEXT_WHITE,
        font=FONT_BODY,
        borderwidth=0,
        focuscolor="none",
        padding=(10, 6)
    )
    style.map(
        "Secondary.TButton",
        background=[("active", "#475569"), ("disabled", "#1e293b")]
    )

    style.configure(
        "Danger.TButton",
        background=COLOR_DANGER,
        foreground=COLOR_TEXT_WHITE,
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(10, 6)
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#dc2626"), ("disabled", COLOR_BORDER)]
    )

    # Treeview table styling
    style.configure(
        "Treeview",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_WHITE,
        fieldbackground=COLOR_CARD_BG,
        rowheight=26,
        font=FONT_BODY,
        borderwidth=0
    )
    style.configure(
        "Treeview.Heading",
        background=COLOR_BORDER,
        foreground=COLOR_TEXT_WHITE,
        font=FONT_BODY_BOLD,
        padding=(6, 4),
        relief="flat"
    )
    style.map(
        "Treeview",
        background=[("selected", COLOR_PRIMARY)],
        foreground=[("selected", COLOR_TEXT_WHITE)]
    )
    style.map(
        "Treeview.Heading",
        background=[("active", "#475569")]
    )

    # Notebook (Tabs)
    style.configure("TNotebook", background=COLOR_BG_DARK, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_MUTED,
        padding=(14, 8),
        font=FONT_BODY_BOLD,
        borderwidth=0
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLOR_PRIMARY), ("active", COLOR_CARD_HOVER)],
        foreground=[("selected", COLOR_TEXT_WHITE), ("active", COLOR_TEXT_WHITE)]
    )

    # Scrollbar
    style.configure(
        "Vertical.TScrollbar",
        background=COLOR_BORDER,
        troughcolor=COLOR_CARD_BG,
        borderwidth=0,
        arrowsize=12
    )
