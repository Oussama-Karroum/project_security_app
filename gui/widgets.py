"""
widgets.py — Shared UI components.
Fixes:
  - Tooltip: removed FocusOut auto-close (was firing instantly).
    Popup stays open until user clicks [X] or clicks button again.
  - Removed duplicate label bug.
  - Fonts enlarged throughout.
  - No emojis.
  - Theme-aware: reads from gui.theme at call time.
"""

import customtkinter as ctk
import tkinter as tk
import gui.theme as T


# ── CIA Badge ─────────────────────────────────────────────────────────

class CIABadge(ctk.CTkFrame):

    _CIA_BG = {
        "C": "BLUE_BG",
        "I": "TEAL_BG",
        "A": "PURPLE_BG",
    }
    _CIA_COLOR = {
        "C": "BLUE",
        "I": "TEAL",
        "A": "PURPLE",
    }

    def __init__(self, parent, cia_keys: list, **kw):
        kw.setdefault("fg_color", "transparent")
        super().__init__(parent, **kw)
        for key in cia_keys:
            color = T.get(self._CIA_COLOR.get(key, "CYAN"))
            bg    = T.get(self._CIA_BG.get(key, "CYAN_BG"))
            label = T.CIA_LABELS.get(key, key)
            ctk.CTkLabel(
                self,
                text=f"  {key} - {label}  ",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=color,
                fg_color=bg,
                corner_radius=10,
            ).pack(side="left", padx=3, pady=2)


# ── Tooltip Button ────────────────────────────────────────────────────

class ToolTipButton(ctk.CTkButton):
    """
    Clickable [?] button that opens a themed popup with a definition.
    - Click button  : opens popup
    - Click button again OR click [X] inside popup : closes popup
    - Popup does NOT close on focus loss (was the bug)
    """

    def __init__(self, parent, term: str, custom_text: str = None, **kw):
        kw.setdefault("text", " ? ")
        kw.setdefault("width", 30)
        kw.setdefault("height", 24)
        kw.setdefault("corner_radius", 5)
        kw.setdefault("font", ctk.CTkFont(size=12, weight="bold"))
        kw.setdefault("fg_color", T.get("BG_HOVER"))
        kw.setdefault("hover_color", T.get("CYAN_HOVER"))
        kw.setdefault("text_color", T.get("CYAN"))
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", T.get("CYAN_BORDER"))
        super().__init__(parent, command=self._toggle, **kw)
        self._term   = term
        self._custom = custom_text
        self._popup  = None

    def _toggle(self):
        # If popup already open, close it
        if self._popup is not None:
            try:
                if self._popup.winfo_exists():
                    self._popup.destroy()
                    self._popup = None
                    return
            except Exception:
                pass
        self._open()

    def _open(self):
        content = self._custom or T.TOOLTIPS.get(
            self._term, f"Pas de definition pour '{self._term}'.")

        bg_deep   = T.get("BG_DEEP")
        bg_card   = T.get("BG_CARD")
        bg_hover  = T.get("BG_HOVER")
        border    = T.get("CYAN_BORDER")
        accent    = T.get("CYAN")
        accent_bg = T.get("CYAN_BG")
        text_code = T.get("TEXT_CODE")
        text_dim  = T.get("TEXT_DIM")

        popup = tk.Toplevel(self)
        popup.overrideredirect(True)
        popup.configure(bg=bg_deep)
        popup.attributes("-topmost", True)   # stay on top

        # Position: below the button
        self.update_idletasks()
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height() + 6
        # Keep on screen
        screen_w = popup.winfo_screenwidth()
        popup.update_idletasks()
        popup.geometry(f"+{min(x, screen_w - 380)}+{y}")

        # Border frame
        outer = tk.Frame(popup, bg=accent, bd=1)
        outer.pack(padx=1, pady=1)

        inner = tk.Frame(outer, bg=bg_card, padx=16, pady=14)
        inner.pack(fill="both", expand=True)

        # Title bar
        title_frame = tk.Frame(inner, bg=accent_bg)
        title_frame.pack(fill="x", pady=(0, 10))

        tk.Label(title_frame,
                 text=f"  {self._term}",
                 bg=accent_bg, fg=accent,
                 font=("Courier", 13, "bold"),
                 padx=6, pady=4,
                 ).pack(side="left")

        # Close button — styled, clearly visible
        close_btn = tk.Label(
            title_frame,
            text="  X  ",
            bg=T.get("RED_BG"), fg=T.get("RED"),
            font=("Courier", 12, "bold"),
            cursor="hand2",
            padx=6, pady=4,
            relief="flat",
        )
        close_btn.pack(side="right", padx=(0, 0))
        close_btn.bind("<Button-1>", lambda e: self._close(popup))

        # Body text
        tk.Label(inner,
                 text=content,
                 bg=bg_card, fg=text_code,
                 font=("Courier", 11),
                 justify="left",
                 wraplength=360,
                 ).pack(anchor="w")

        # Bottom close button
        bottom = tk.Frame(inner, bg=bg_card)
        bottom.pack(fill="x", pady=(12, 0))

        close_bottom = tk.Label(
            bottom,
            text="  Fermer  ",
            bg=T.get("RED_BG"), fg=T.get("RED"),
            font=("Courier", 11, "bold"),
            cursor="hand2",
            padx=8, pady=4,
            relief="flat",
        )
        close_bottom.pack(side="right")
        close_bottom.bind("<Button-1>", lambda e: self._close(popup))

        self._popup = popup

    def _close(self, popup):
        try:
            popup.destroy()
        except Exception:
            pass
        self._popup = None


# ── Terminal Box ──────────────────────────────────────────────────────

class TerminalBox(ctk.CTkTextbox):
    """Dark monospace read-only output box. Reads colors from theme at creation."""

    def __init__(self, parent, height=100, **kw):
        kw.setdefault("font", ctk.CTkFont(family="Courier", size=12))
        kw.setdefault("fg_color", T.get("BG_DEEP"))
        kw.setdefault("text_color", T.get("TEXT_CODE"))
        kw.setdefault("border_color", T.get("BORDER"))
        kw.setdefault("border_width", 1)
        kw.setdefault("corner_radius", T.RADIUS)
        super().__init__(parent, height=height, **kw)

    def set_text(self, text: str):
        self.configure(state="normal")
        self.delete("0.0", "end")
        self.insert("0.0", text)
        self.configure(state="disabled")

    def append(self, text: str):
        self.configure(state="normal")
        self.insert("end", text)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("0.0", "end")
        self.configure(state="disabled")


# ── Section Card ──────────────────────────────────────────────────────

class SectionCard(ctk.CTkFrame):
    """Raised card with a coloured title bar. Theme-aware."""

    def __init__(self, parent, title: str, accent: str = None,
                 cia_keys: list = None, **kw):
        if accent is None:
            accent = T.get("CYAN")

        # Map accent to its bg tint key
        _tint_map = {
            T.get("CYAN"):   "CYAN_BG",
            T.get("GREEN"):  "GREEN_BG",
            T.get("AMBER"):  "AMBER_BG",
            T.get("RED"):    "RED_BG",
            T.get("PURPLE"): "PURPLE_BG",
            T.get("BLUE"):   "BLUE_BG",
            T.get("TEAL"):   "TEAL_BG",
        }
        title_bg = T.get(_tint_map.get(accent, "BG_HOVER"))

        kw.setdefault("fg_color", T.get("BG_CARD"))
        kw.setdefault("corner_radius", T.RADIUS)
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", T.get("BORDER"))
        super().__init__(parent, **kw)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Title bar
        tbar = ctk.CTkFrame(self, fg_color=title_bg, corner_radius=0, height=36)
        tbar.grid(row=0, column=0, sticky="ew")
        tbar.grid_columnconfigure(0, weight=1)
        tbar.grid_propagate(False)

        ctk.CTkLabel(tbar, text=title,
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=accent,
                     ).grid(row=0, column=0, padx=12, sticky="w")

        if cia_keys:
            CIABadge(tbar, cia_keys).grid(row=0, column=1, padx=8, sticky="e")

        # Content
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.content.grid_columnconfigure(0, weight=1)


# ── Status Bar ────────────────────────────────────────────────────────

class StatusBar(ctk.CTkLabel):

    _ICONS  = {"ok": "[OK]", "error": "[ERREUR]", "warning": "[AVERT]",
               "info": "[INFO]", "loading": "[...]", "attack": "[ATTAQUE]"}
    _CKEYS  = {"ok": "GREEN", "error": "RED", "warning": "AMBER",
               "info": "CYAN", "loading": "AMBER", "attack": "RED"}

    def __init__(self, parent, **kw):
        kw.setdefault("text", "")
        kw.setdefault("font", ctk.CTkFont(size=12))
        kw.setdefault("anchor", "w")
        super().__init__(parent, **kw)

    def set(self, msg: str, level: str = "info"):
        icon  = self._ICONS.get(level, "")
        color = T.get(self._CKEYS.get(level, "CYAN"))
        self.configure(text=f"{icon}  {msg}", text_color=color)

    def clear(self):
        self.configure(text="")


# ── Accent Button factory ─────────────────────────────────────────────

def accent_btn(parent, text, command, color_key: str,
               width=140, height=30, **kw):
    """
    color_key: base color name as in theme, e.g. 'BLUE', 'RED', 'CYAN'.
    Reads tints from theme at call time — always current mode.
    """
    fg    = T.get(color_key + "_BG")
    hover = T.get(color_key + "_HOVER")
    bord  = T.get(color_key + "_BORDER")
    text_color = T.get(color_key)
    return ctk.CTkButton(
        parent, text=text, command=command,
        width=width, height=height,
        fg_color=fg, hover_color=hover,
        text_color=text_color,
        border_width=1, border_color=bord,
        **kw
    )
