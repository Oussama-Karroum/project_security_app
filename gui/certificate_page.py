"""
certificate_page.py — X.509 self-signed certificate. All colors 6-char hex.
"""

import customtkinter as ctk
from tkinter import filedialog

from core.certificate import CertificateManager
import gui.theme as T

from gui.widgets import CIABadge, ToolTipButton, TerminalBox, SectionCard, StatusBar


def _btn(parent, text, cmd, fg, tc, bc, hc, width=160, height=32):
    return ctk.CTkButton(parent, text=text, command=cmd, width=width, height=height,
                          fg_color=fg, hover_color=hc, text_color=tc,
                          border_width=1, border_color=bc)


class CertificatePage(ctk.CTkScrollableFrame):

    INFO = (
        "Objectif CIA : AUTHENTICITÉ — lier une clé publique à une identité vérifiée.\n"
        "Un certificat X.509 est signé par une Autorité de Certification (CA). "
        "Un certificat auto-signé est signé par son propre détenteur (usage interne / test).\n"
        "Historique : X.509 v3 (1996, RFC 5280) — standard TLS/HTTPS, S/MIME, code signing."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color=T.get("BG_DEEP"), scrollbar_button_color=T.get("BORDER"))
        self.grid_columnconfigure(0, weight=1)
        self.cm        = CertificateManager()
        self._cert     = None
        self._cert_key = None
        self._build()

    def _build(self):
        self._header()
        self._generate_section()
        self._inspect_section()
        self._pem_section()

    def _header(self):
        f = ctk.CTkFrame(self, fg_color=T.get("BG_CARD"), corner_radius=8,
                         border_width=1, border_color=T.get("BORDER"))
        f.grid(row=0, column=0, padx=14, pady=(14, 6), sticky="ew")
        f.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="📜  CERTIFICAT NUMÉRIQUE",
                     font=ctk.CTkFont(family="Courier", size=15, weight="bold"),
                     text_color=T.get("CYAN")).grid(row=0, column=0, sticky="w")
        CIABadge(top, ["A"]).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(f, text=self.INFO, font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"), wraplength=820, justify="left",
                     ).grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")

    def _generate_section(self):
        card = SectionCard(self, title="  🏗️   Générer un Certificat Auto-Signé",
                           accent=T.get("CYAN"), cia_keys=["A"])
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(1, weight=1)

        fields = [
            ("Common Name (CN) :",   "cn",      "ensaf.ac.ma",  "certificat"),
            ("Organisation (O) :",   "org",     "ENSAF",        None),
            ("Pays (C) 2 lettres :", "country", "MA",           None),
            ("État / Région :",      "state",   "Fes-Meknes",   None),
            ("Localité :",           "city",    "Fes",          None),
            ("Validité (jours) :",   "days",    "365",          None),
        ]
        self._fields = {}
        for i, (label, key, ph, tip) in enumerate(fields):
            lf = ctk.CTkFrame(c, fg_color="transparent")
            lf.grid(row=i, column=0, padx=(0, 6), pady=5, sticky="w")
            ctk.CTkLabel(lf, text=label,
                         font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                         text_color=T.get("CYAN")).pack(side="left")
            if tip:
                ToolTipButton(lf, tip).pack(side="left", padx=4)
            entry = ctk.CTkEntry(c, placeholder_text=ph,
                                 fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"),
                                 text_color=T.get("TEXT_DIM"))
            entry.grid(row=i, column=1, padx=4, pady=5, sticky="ew")
            self._fields[key] = entry

        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=len(fields), column=0, columnspan=2, pady=8, sticky="w")
        for txt, cmd, fg, tc, bc, hc in [
            ("📜 Générer", self._generate, T.get("CYAN_BG"),  T.get("CYAN"),  T.get("CYAN_BORDER"),  T.get("CYAN_HOVER")),
            ("💾 Sauver",  self._save,     T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER")),
            ("📂 Charger", self._load,     T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER")),
        ]:
            _btn(bf, txt, cmd, fg, tc, bc, hc, 150, 32).pack(side="left", padx=3)

        self.gen_status = StatusBar(c)
        self.gen_status.grid(row=len(fields)+1, column=0, columnspan=2, pady=4, sticky="w")

    def _inspect_section(self):
        card = SectionCard(self, title="  🔍  Informations du Certificat",
                           accent=T.get("GREEN"), cia_keys=["A"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        self.inspect_box = TerminalBox(c, height=260)
        self.inspect_box.grid(row=0, column=0, pady=4, sticky="ew")
        self.inspect_box.set_text("Générez ou chargez un certificat pour voir ses informations ici.")

    def _pem_section(self):
        card = SectionCard(self, title="  📄  Contenu PEM Brut",
                           accent=T.get("PURPLE"), cia_keys=["A"])
        card.grid(row=3, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        self.pem_box = TerminalBox(c, height=200)
        self.pem_box.grid(row=0, column=0, pady=4, sticky="ew")
        self.pem_box.set_text("Le contenu PEM s'affichera ici.")

    # ── Handlers ──────────────────────────────────────────────────────

    def _generate(self):
        try:
            self.gen_status.set("Génération RSA-2048 + certificat...", "loading"); self.update()
            days_s = self._fields["days"].get().strip()
            days   = int(days_s) if days_s.isdigit() else 365
            info   = {
                "common_name":  self._fields["cn"].get().strip()      or "ensaf.ac.ma",
                "organization": self._fields["org"].get().strip()     or "ENSAF",
                "country":      self._fields["country"].get().strip() or "MA",
                "state":        self._fields["state"].get().strip()   or "Fes-Meknes",
                "locality":     self._fields["city"].get().strip()    or "Fes",
            }
            self._cert, self._cert_key = self.cm.generate_self_signed_cert(info, days)
            self._refresh()
            self.gen_status.set(f"Certificat auto-signé généré — valide {days} jours.", "ok")
        except Exception as e:
            self.gen_status.set(str(e), "error")

    def _save(self):
        if not self._cert:
            self.gen_status.set("Générez d'abord un certificat.", "warning"); return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                             initialfile="certificate.pem")
        if not path: return
        self.cm.save_certificate(self._cert, path)
        if self._cert_key:
            self.cm.save_private_key(self._cert_key, path.replace(".pem", "_key.pem"))
        self.gen_status.set(f"Certificat sauvegardé → {path}", "ok")

    def _load(self):
        path = filedialog.askopenfilename(filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if not path: return
        try:
            self._cert     = self.cm.load_certificate(path)
            self._cert_key = None
            self._refresh()
            self.gen_status.set(f"Certificat chargé.", "ok")
        except Exception as e:
            self.gen_status.set(str(e), "error")

    def _refresh(self):
        if not self._cert: return
        info = self.cm.extract_info(self._cert)
        self.inspect_box.set_text(self.cm.format_info_display(info))
        self.pem_box.set_text(self.cm.export_pem(self._cert))
