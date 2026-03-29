"""
Module: main_window.py
Class:  MainApp
Role:   Root CustomTkinter window — sidebar navigation, theme toggle, page switching
"""

import customtkinter as ctk
from gui.confidentiality_page import ConfidentialityPage
from gui.integrity_page        import IntegrityPage
from gui.signature_page        import SignaturePage
from gui.certificate_page      import CertificatePage
from gui.performance_page      import PerformancePage


# ── Global theme defaults ────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class MainApp(ctk.CTk):
    """
    Root application window.

    Builds a two-column layout:
      LEFT  — fixed sidebar with navigation buttons + theme toggle
      RIGHT — dynamic content area that swaps pages
    """

    WIDTH  = 1100
    HEIGHT = 720

    NAV_ITEMS = [
        ("🔒  Confidentialité", "confidentiality"),
        ("🔗  Intégrité",        "integrity"),
        ("✍️   Signature",        "signature"),
        ("📜  Certificat",       "certificate"),
        ("⚡  Performance",      "performance"),
    ]

    def __init__(self):
        super().__init__()
        self.title("🔐 CryptoApp — ENSAF | Prof. Said Hraoui")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(900, 600)
        self.resizable(True, True)

        self._current_page = None
        self._nav_buttons  = {}
        self._pages        = {}

        self._build_layout()
        self._build_sidebar()
        self._build_content_area()
        self._register_pages()
        self._show_page("confidentiality")   # default landing page

    # ── Layout skeleton ──────────────────────────────────────────────

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(len(self.NAV_ITEMS) + 2, weight=1)

        # Logo / title
        logo = ctk.CTkLabel(
            self.sidebar,
            text="🔐 CryptoApp",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#1a73e8", "#4fc3f7"),
        )
        logo.grid(row=0, column=0, padx=20, pady=(24, 4))

        subtitle = ctk.CTkLabel(
            self.sidebar,
            text="ENSAF — Cryptographie",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation buttons
        for idx, (label, key) in enumerate(self.NAV_ITEMS):
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor="w",
                font=ctk.CTkFont(size=13),
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                height=40,
                corner_radius=8,
                command=lambda k=key: self._show_page(k),
            )
            btn.grid(row=idx + 2, column=0, padx=12, pady=3, sticky="ew")
            self._nav_buttons[key] = btn

        # Spacer then theme toggle at bottom
        theme_label = ctk.CTkLabel(self.sidebar, text="Apparence", font=ctk.CTkFont(size=11), text_color="gray")
        theme_label.grid(row=len(self.NAV_ITEMS) + 3, column=0, padx=20, pady=(0, 4))

        self.theme_switch = ctk.CTkOptionMenu(
            self.sidebar,
            values=["Sombre", "Clair", "Système"],
            command=self._change_theme,
            width=160,
        )
        self.theme_switch.set("Sombre")
        self.theme_switch.grid(row=len(self.NAV_ITEMS) + 4, column=0, padx=20, pady=(0, 20))

    def _build_content_area(self):
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray95", "gray10"))
        self.content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    def _register_pages(self):
        """Instantiate all pages and store them — they share the same content frame."""
        self._pages = {
            "confidentiality": ConfidentialityPage(self.content),
            "integrity":       IntegrityPage(self.content),
            "signature":       SignaturePage(self.content),
            "certificate":     CertificatePage(self.content),
            "performance":     PerformancePage(self.content),
        }

    # ── Navigation ───────────────────────────────────────────────────

    def _show_page(self, key: str):
        """Hide current page, show requested page, update button highlights."""
        if self._current_page:
            self._pages[self._current_page].grid_remove()

        # Highlight active button
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(
                    fg_color=("gray75", "gray25"),
                    text_color=("#1a73e8", "#4fc3f7"),
                    font=ctk.CTkFont(size=13, weight="bold"),
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=("gray10", "gray90"),
                    font=ctk.CTkFont(size=13, weight="normal"),
                )

        self._pages[key].grid(row=0, column=0, sticky="nsew")
        self._current_page = key

    # ── Theme ────────────────────────────────────────────────────────

    def _change_theme(self, choice: str):
        mapping = {"Sombre": "dark", "Clair": "light", "Système": "system"}
        ctk.set_appearance_mode(mapping.get(choice, "dark"))
