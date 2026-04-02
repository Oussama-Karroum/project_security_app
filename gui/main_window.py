"""
main_window.py — Root window.
- Dark / Light theme switch that actually works (rebuilds pages).
- Bigger fonts throughout.
- Wider scrollbar on content pages.
- No emojis, no school/professor name.
"""

import customtkinter as ctk
import gui.theme as T

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class MainApp(ctk.CTk):

    WIDTH  = 1200
    HEIGHT = 780

    NAV_ITEMS = [
        ("Confidentialite",  "confidentiality"),
        ("Integrite",        "integrity"),
        ("Signature",        "signature"),
        ("Certificat",       "certificate"),
        ("Performance",      "performance"),
    ]

    def __init__(self):
        super().__init__()
        self.title("CryptoLab — Application de Cryptographie")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(980, 660)
        self._current    = None
        self._nav_btns   = {}
        self._pages      = {}
        self._mode       = "dark"
        self._apply_window_bg()
        self._build()

    # ── Build ─────────────────────────────────────────────────────────

    def _build(self):
        # Clear any existing layout
        for w in self.winfo_children():
            w.destroy()
        self._nav_btns = {}
        self._pages    = {}
        self._current  = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._topbar()
        self._sidebar()
        self._content_area()
        self._register_pages()
        self._show("confidentiality")

    def _apply_window_bg(self):
        self.configure(fg_color=T.get("BG_DEEP"))

    # ── Top bar ───────────────────────────────────────────────────────

    def _topbar(self):
        bar = ctk.CTkFrame(self, height=48,
                           fg_color=T.get("BG_CARD"),
                           corner_radius=0,
                           border_width=1,
                           border_color=T.get("BORDER"))
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bar,
                     text="CryptoLab",
                     font=ctk.CTkFont(family="Courier", size=18, weight="bold"),
                     text_color=T.get("CYAN"),
                     ).grid(row=0, column=0, padx=20, sticky="w")

        ctk.CTkLabel(bar,
                     text="Application de Cryptographie",
                     font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"),
                     ).grid(row=0, column=1, padx=8, sticky="w")

        self._theme_menu = ctk.CTkOptionMenu(
            bar,
            values=["Mode sombre", "Mode clair"],
            command=self._switch_theme,
            width=140, height=30,
            fg_color=T.get("BG_HOVER"),
            button_color=T.get("CYAN_BORDER"),
            button_hover_color=T.get("CYAN_HOVER"),
            text_color=T.get("TEXT_BRIGHT"),
            font=ctk.CTkFont(size=13),
        )
        self._theme_menu.set("Mode sombre" if self._mode == "dark" else "Mode clair")
        self._theme_menu.grid(row=0, column=2, padx=16)

    # ── Sidebar ───────────────────────────────────────────────────────

    def _sidebar(self):
        sb = ctk.CTkFrame(self, width=210,
                          fg_color=T.get("BG_CARD"),
                          corner_radius=0,
                          border_width=1,
                          border_color=T.get("BORDER"))
        sb.grid(row=1, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(len(self.NAV_ITEMS) + 2, weight=1)

        ctk.CTkLabel(sb,
                     text="NAVIGATION",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("TEXT_DIM"),
                     ).grid(row=0, column=0, padx=16, pady=(20, 10), sticky="w")

        for i, (label, key) in enumerate(self.NAV_ITEMS):
            btn = ctk.CTkButton(
                sb,
                text=f"   {label}",
                anchor="w",
                font=ctk.CTkFont(family="Courier", size=14),
                fg_color="transparent",
                text_color=T.get("TEXT_DIM"),
                hover_color=T.get("BG_HOVER"),
                height=44,
                corner_radius=6,
                border_width=0,
                command=lambda k=key: self._show(k),
            )
            btn.grid(row=i + 1, column=0, padx=8, pady=3, sticky="ew")
            self._nav_btns[key] = btn

        ctk.CTkLabel(sb,
                     text="v2.1",
                     font=ctk.CTkFont(family="Courier", size=10),
                     text_color=T.get("TEXT_DIM"),
                     ).grid(row=99, column=0, padx=16, pady=14, sticky="sw")

    # ── Content area ──────────────────────────────────────────────────

    def _content_area(self):
        self.content = ctk.CTkFrame(self,
                                     corner_radius=0,
                                     fg_color=T.get("BG_DEEP"))
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    # ── Pages ─────────────────────────────────────────────────────────

    def _register_pages(self):
        from gui.confidentiality_page import ConfidentialityPage
        from gui.integrity_page       import IntegrityPage
        from gui.signature_page       import SignaturePage
        from gui.certificate_page     import CertificatePage
        from gui.performance_page     import PerformancePage

        self._pages = {
            "confidentiality": ConfidentialityPage(self.content),
            "integrity":       IntegrityPage(self.content),
            "signature":       SignaturePage(self.content),
            "certificate":     CertificatePage(self.content),
            "performance":     PerformancePage(self.content),
        }

    # ── Navigation ────────────────────────────────────────────────────

    def _show(self, key: str):
        if self._current:
            self._pages[self._current].grid_remove()

        for k, btn in self._nav_btns.items():
            if k == key:
                btn.configure(
                    fg_color=T.get("CYAN_HOVER"),
                    text_color=T.get("CYAN"),
                    font=ctk.CTkFont(family="Courier", size=14, weight="bold"),
                    border_width=1,
                    border_color=T.get("CYAN_BORDER"),
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=T.get("TEXT_DIM"),
                    font=ctk.CTkFont(family="Courier", size=14),
                    border_width=0,
                )

        self._pages[key].grid(row=0, column=0, sticky="nsew")
        self._current = key

    # ── Theme switch ──────────────────────────────────────────────────

    def _switch_theme(self, choice: str):
        self._mode = "dark" if choice == "Mode sombre" else "light"

        # 1. Update CTk appearance
        ctk.set_appearance_mode(self._mode)

        # 2. Update theme module palette
        T.set_mode(self._mode)
        T._export()
        T._update_cia()

        # 3. Rebuild the entire UI with new colors
        self._apply_window_bg()
        self._build()
