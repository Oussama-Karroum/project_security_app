"""
Module: certificate_page.py
Role:   GUI page for X.509 self-signed certificate generation and inspection
        Calls core.certificate — zero crypto code here
"""

import customtkinter as ctk
from tkinter import filedialog
from core.certificate import CertificateManager


class CertificatePage(ctk.CTkFrame):
    """
    Certificate page — generate self-signed X.509 cert, inspect its fields.

    CIA Objective : Authentication (identity binding)
    """

    INFO_TEXT = (
        "📜  CERTIFICAT NUMÉRIQUE\n\n"
        "Objectif CIA : Authentification — lier une clé publique à une identité vérifiée.\n\n"
        "• Un certificat X.509 contient : identité du sujet, clé publique, période de validité,\n"
        "  numéro de série, signature de l'émetteur (CA).\n"
        "• Un certificat auto-signé : l'émetteur et le sujet sont identiques (pas de CA).\n"
        "  Utilisé pour les tests, les environnements internes, ou les PKI privées.\n\n"
        "• Limite : Non reconnu par défaut par les navigateurs/OS sans installation manuelle.\n"
        "  En production, un CA de confiance (Let's Encrypt, DigiCert…) doit signer le certificat."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.cm   = CertificateManager()
        self._cert     = None
        self._cert_key = None

        self._build_info_banner()
        self._build_tabs()

    def _build_info_banner(self):
        banner = ctk.CTkTextbox(self, height=148, wrap="word", font=ctk.CTkFont(size=12))
        banner.insert("0.0", self.INFO_TEXT)
        banner.configure(state="disabled")
        banner.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.tabs.add("🏗️  Générer")
        self.tabs.add("🔍  Inspecter")
        self.tabs.add("📄  PEM brut")

        self._build_generate_tab(self.tabs.tab("🏗️  Générer"))
        self._build_inspect_tab(self.tabs.tab("🔍  Inspecter"))
        self._build_pem_tab(self.tabs.tab("📄  PEM brut"))

    # ── Generate tab ─────────────────────────────────────────────────

    def _build_generate_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        fields = [
            ("Common Name (CN) :",    "cn",      "ensaf.ac.ma"),
            ("Organisation (O) :",    "org",     "ENSAF"),
            ("Pays (C) — 2 lettres:", "country", "MA"),
            ("État / Région (ST) :",  "state",   "Fes-Meknes"),
            ("Localité (L) :",        "city",    "Fes"),
        ]

        self._field_entries = {}
        for i, (label, key, placeholder) in enumerate(fields):
            ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(weight="bold")).grid(
                row=i, column=0, padx=(8,4), pady=6, sticky="w")
            entry = ctk.CTkEntry(parent, placeholder_text=placeholder)
            entry.grid(row=i, column=1, padx=(4,8), pady=6, sticky="ew")
            self._field_entries[key] = entry

        # Validity
        ctk.CTkLabel(parent, text="Validité (jours) :", font=ctk.CTkFont(weight="bold")).grid(
            row=len(fields), column=0, padx=(8,4), pady=6, sticky="w")
        self.validity_entry = ctk.CTkEntry(parent, placeholder_text="365")
        self.validity_entry.grid(row=len(fields), column=1, padx=(4,8), pady=6, sticky="ew")

        # Buttons
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=len(fields)+1, column=0, columnspan=2, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(btn_frame, text="📜 Générer certificat auto-signé",
                      command=self._generate_cert, height=40).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="💾 Sauvegarder (.pem)",
                      command=self._save_cert).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="📂 Charger un certificat",
                      command=self._load_cert).pack(side="left", padx=4)

        self.gen_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.gen_status.grid(row=len(fields)+2, column=0, columnspan=2, padx=8, pady=4, sticky="w")

    # ── Inspect tab ──────────────────────────────────────────────────

    def _build_inspect_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        self.inspect_display = ctk.CTkTextbox(
            parent, font=ctk.CTkFont(family="Courier", size=12))
        self.inspect_display.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.inspect_display.insert("0.0", "Générez ou chargez un certificat pour voir ses informations ici.")
        self.inspect_display.configure(state="disabled")

    # ── PEM tab ──────────────────────────────────────────────────────

    def _build_pem_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        self.pem_display = ctk.CTkTextbox(
            parent, font=ctk.CTkFont(family="Courier", size=11))
        self.pem_display.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.pem_display.insert("0.0", "Le contenu PEM du certificat s'affichera ici.")
        self.pem_display.configure(state="disabled")

    # ── Handlers ─────────────────────────────────────────────────────

    def _generate_cert(self):
        try:
            self._set_status(self.gen_status, "⏳ Génération du certificat...", "orange")
            self.update()

            validity_str = self.validity_entry.get().strip()
            validity     = int(validity_str) if validity_str.isdigit() else 365

            info = {
                "common_name":  self._field_entries["cn"].get().strip()      or "ensaf.ac.ma",
                "organization": self._field_entries["org"].get().strip()     or "ENSAF",
                "country":      self._field_entries["country"].get().strip() or "MA",
                "state":        self._field_entries["state"].get().strip()   or "Fes-Meknes",
                "locality":     self._field_entries["city"].get().strip()    or "Fes",
            }

            self._cert, self._cert_key = self.cm.generate_self_signed_cert(info, validity)
            self._refresh_displays()
            self._set_status(self.gen_status, "✅ Certificat auto-signé généré avec succès.", "green")
        except Exception as e:
            self._set_status(self.gen_status, f"❌ {e}", "red")

    def _save_cert(self):
        try:
            if not self._cert:
                raise ValueError("Générez d'abord un certificat.")
            path = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM", "*.pem"), ("All", "*.*")],
                initialfile="certificate.pem"
            )
            if not path:
                return
            self.cm.save_certificate(self._cert, path)
            key_path = path.replace(".pem", "_key.pem")
            self.cm.save_private_key(self._cert_key, key_path)
            self._set_status(self.gen_status, f"✅ Certificat sauvegardé → {path}", "green")
        except Exception as e:
            self._set_status(self.gen_status, f"❌ {e}", "red")

    def _load_cert(self):
        try:
            path = filedialog.askopenfilename(
                title="Charger un certificat PEM",
                filetypes=[("PEM", "*.pem"), ("All", "*.*")]
            )
            if not path:
                return
            self._cert = self.cm.load_certificate(path)
            self._cert_key = None
            self._refresh_displays()
            self._set_status(self.gen_status, f"✅ Certificat chargé : {path}", "green")
        except Exception as e:
            self._set_status(self.gen_status, f"❌ {e}", "red")

    def _refresh_displays(self):
        """Update inspect and PEM tabs after generating or loading a certificate."""
        if not self._cert:
            return

        # Inspect tab
        info        = self.cm.extract_info(self._cert)
        info_text   = self.cm.format_info_display(info)
        self._set_textbox(self.inspect_display, info_text)

        # PEM tab
        pem_text = self.cm.export_pem(self._cert)
        self._set_textbox(self.pem_display, pem_text)

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_textbox(widget, text):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _set_status(label, text, color):
        label.configure(text=text, text_color=color)
