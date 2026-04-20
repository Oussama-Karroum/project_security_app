import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import threading, time, os

from core.symmetric  import SymmetricCipher
from core.asymmetric import AsymmetricCipher
import gui.theme as T

from gui.widgets import CIABadge, ToolTipButton, TerminalBox, SectionCard, StatusBar


def _btn(parent, text, cmd, accent_fg, accent_text, accent_border, accent_hover,
         width=140, height=30):
    return ctk.CTkButton(
        parent, text=text, command=cmd, width=width, height=height,
        fg_color=accent_fg, hover_color=accent_hover,
        text_color=accent_text, border_width=1, border_color=accent_border,
    )


class ConfidentialityPage(ctk.CTkScrollableFrame):

    INFO = (
        "Objectif CIA : CONFIDENTIALITÉ — seul le destinataire autorisé peut lire les données.\n"
        "AES-256-CBC (symétrique) est ~400× plus rapide que RSA, mais impose un problème de "
        "distribution de clé. RSA (asymétrique) résout ce problème via une paire clé publique / privée.\n"
        "Le chiffrement HYBRIDE combine les deux : AES chiffre les données, RSA chiffre la clé AES."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color=T.get("BG_DEEP"), scrollbar_button_color=T.get("BORDER"))
        self.grid_columnconfigure(0, weight=1)
        self.sym  = SymmetricCipher()
        self.asym = AsymmetricCipher()
        self._aes_key    = None
        self._rsa_priv   = None
        self._rsa_pub    = None
        self._hybrid_enc = None
        self._build()

    def _build(self):
        self._header()
        self._aes_section()
        self._rsa_section()
        self._hybrid_section()
        self._attack_section()

    # ── Header ────────────────────────────────────────────────────────

    def _header(self):
        f = ctk.CTkFrame(self, fg_color=T.get("BG_CARD"), corner_radius=8,
                         border_width=1, border_color=T.get("BORDER"))
        f.grid(row=0, column=0, padx=14, pady=(14, 6), sticky="ew")
        f.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="CONFIDENTIALITÉ",
                     font=ctk.CTkFont(family="Courier", size=15, weight="bold"),
                     text_color=T.get("CYAN")).grid(row=0, column=0, sticky="w")
        CIABadge(top, ["C"]).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(f, text=self.INFO, font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"), wraplength=820, justify="left",
                     ).grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")

    # ── AES Section ───────────────────────────────────────────────────

    def _aes_section(self):
        card = SectionCard(self, title="  AES-256-CBC  —  Chiffrement Symétrique",
                           accent=T.get("BLUE"), cia_keys=["C"])
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(1, weight=1)

        # Key row
        ctk.CTkLabel(c, text="Clé AES :",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("BLUE")).grid(row=0, column=0, padx=(0, 6), pady=6, sticky="w")
        self.aes_key_entry = ctk.CTkEntry(
            c, font=ctk.CTkFont(family="Courier", size=13),
            fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"), text_color=T.get("TEXT_CODE"),
            placeholder_text="hex 256-bit — générez ou importez")
        self.aes_key_entry.grid(row=0, column=1, padx=4, pady=6, sticky="ew")

        kbf = ctk.CTkFrame(c, fg_color="transparent")
        kbf.grid(row=0, column=2, padx=4, pady=6)
        for txt, cmd in [("Générer", self._aes_gen), ("Importer", self._aes_import),
                          ("Exporter", self._aes_export)]:
            _btn(kbf, txt, cmd, T.get("BLUE_BG"), T.get("BLUE"), T.get("BLUE_BORDER"), T.get("BLUE_HOVER"),
                 width=82, height=28).pack(side="left", padx=2)
        ToolTipButton(kbf, "IV").pack(side="left", padx=4)
        ToolTipButton(kbf, "AES").pack(side="left", padx=2)

        # Texte à chiffrer
        ctk.CTkLabel(c, text="Texte à chiffrer :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=1, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                         border_color=T.get("BORDER"), border_width=1)
        self.aes_input.grid(row=1, column=1, columnspan=2, padx=4, pady=4, sticky="ew")

        abf = ctk.CTkFrame(c, fg_color="transparent")
        abf.grid(row=2, column=0, columnspan=3, pady=4, sticky="w")
        for txt, cmd in [("Chiffrer", self._aes_enc),
                          ("Chiffrer fichier", self._aes_enc_file),
                          ("Effacer", self._aes_clear)]:
            _btn(abf, txt, cmd, T.get("BLUE_BG"), T.get("BLUE"), T.get("BLUE_BORDER"), T.get("BLUE_HOVER"),
                 width=148, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Ciphertext AES (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=3, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_output = TerminalBox(c, height=55)
        self.aes_output.grid(row=3, column=1, padx=4, pady=4, sticky="ew")
        copy_btn = ctk.CTkButton(c, text="Copier", command=lambda: self.aes_output.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=3, column=2, padx=4, pady=4, sticky="w")

        # Déchiffrement séparé
        ctk.CTkLabel(c, text="Ciphertext à déchiffrer :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=4, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_dec_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                             border_color=T.get("BORDER"), border_width=1)
        self.aes_dec_input.grid(row=4, column=1, columnspan=2, padx=4, pady=4, sticky="ew")

        dbf = ctk.CTkFrame(c, fg_color="transparent")
        dbf.grid(row=5, column=0, columnspan=3, pady=4, sticky="w")
        for txt, cmd in [("Déchiffrer", self._aes_dec),
                          ("Déchiffrer fichier", self._aes_dec_file)]:
            _btn(dbf, txt, cmd, T.get("BLUE_BG"), T.get("BLUE"), T.get("BLUE_BORDER"), T.get("BLUE_HOVER"),
                 width=148, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Texte déchiffré :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=6, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_dec_output = TerminalBox(c, height=55)
        self.aes_dec_output.grid(row=6, column=1, padx=4, pady=4, sticky="ew")
        copy_btn2 = ctk.CTkButton(c, text="Copier", command=lambda: self.aes_dec_output.copy_to_clipboard(),
                                  width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                  text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn2.grid(row=6, column=2, padx=4, pady=4, sticky="w")

        self.aes_status = StatusBar(c)
        self.aes_status.grid(row=7, column=0, columnspan=3, pady=3, sticky="w")

    # ── RSA Section ───────────────────────────────────────────────────

    def _rsa_section(self):
        card = SectionCard(self, title="  RSA-2048  —  Chiffrement Asymétrique",
                           accent=T.get("PURPLE"), cia_keys=["C"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        kbf = ctk.CTkFrame(c, fg_color="transparent")
        kbf.grid(row=0, column=0, pady=4, sticky="ew")
        for txt, cmd in [("Générer RSA-2048", self._rsa_gen),
                          ("Importer clé privée", self._rsa_import_priv),
                          ("Exporter clés", self._rsa_export)]:
            _btn(kbf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 width=170, height=30).pack(side="left", padx=3)
        ToolTipButton(kbf, "RSA").pack(side="left", padx=4)
        ToolTipButton(kbf, "OAEP").pack(side="left", padx=2)

        self.rsa_key_status = StatusBar(c)
        self.rsa_key_status.set("Aucune clé RSA chargée", "warning")
        self.rsa_key_status.grid(row=1, column=0, pady=2, sticky="w")

        # Chiffrement RSA
        ctk.CTkLabel(c, text="Texte à chiffrer (≤ 190 octets) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(6, 0), sticky="w")
        self.rsa_input = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                         border_color=T.get("BORDER"), border_width=1)
        self.rsa_input.grid(row=3, column=0, pady=4, sticky="ew")

        rbf = ctk.CTkFrame(c, fg_color="transparent")
        rbf.grid(row=4, column=0, pady=4, sticky="w")
        for txt, cmd in [("Chiffrer RSA", self._rsa_enc),
                          ("Chiffrer fichier", self._rsa_enc_file)]:
            _btn(rbf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 width=160, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Ciphertext RSA (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=5, column=0, pady=(6, 0), sticky="w")
        rsa_out_frame = ctk.CTkFrame(c, fg_color="transparent")
        rsa_out_frame.grid(row=6, column=0, pady=4, sticky="ew")
        rsa_out_frame.grid_columnconfigure(0, weight=1)
        self.rsa_output = TerminalBox(rsa_out_frame, height=55)
        self.rsa_output.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(rsa_out_frame, text="Copier", command=lambda: self.rsa_output.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")

        # Déchiffrement RSA séparé
        ctk.CTkLabel(c, text="Ciphertext à déchiffrer :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=7, column=0, pady=(6, 0), sticky="w")
        self.rsa_dec_input = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                             border_color=T.get("BORDER"), border_width=1)
        self.rsa_dec_input.grid(row=8, column=0, pady=4, sticky="ew")

        dbf = ctk.CTkFrame(c, fg_color="transparent")
        dbf.grid(row=9, column=0, pady=4, sticky="w")
        for txt, cmd in [("Déchiffrer RSA", self._rsa_dec),
                          ("Déchiffrer fichier", self._rsa_dec_file)]:
            _btn(dbf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 width=160, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Texte déchiffré :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=10, column=0, pady=(6, 0), sticky="w")
        rsa_dec_out_frame = ctk.CTkFrame(c, fg_color="transparent")
        rsa_dec_out_frame.grid(row=11, column=0, pady=4, sticky="ew")
        rsa_dec_out_frame.grid_columnconfigure(0, weight=1)
        self.rsa_dec_output = TerminalBox(rsa_dec_out_frame, height=55)
        self.rsa_dec_output.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn2 = ctk.CTkButton(rsa_dec_out_frame, text="Copier", command=lambda: self.rsa_dec_output.copy_to_clipboard(),
                                  width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                  text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn2.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")

        self.rsa_status = StatusBar(c)
        self.rsa_status.grid(row=12, column=0, pady=2, sticky="w")

    # ── Hybrid Section ────────────────────────────────────────────────

    def _hybrid_section(self):
        card = SectionCard(self, title="  Hybride RSA+AES  —  Schéma Industriel",
                           accent=T.get("CYAN"), cia_keys=["C"])
        card.grid(row=3, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        tip_row = ctk.CTkFrame(c, fg_color="transparent")
        tip_row.grid(row=0, column=0, pady=4, sticky="w")
        ToolTipButton(tip_row, "hybride").pack(side="left", padx=2)
        ctk.CTkLabel(tip_row,
                     text="AES chiffre les données · RSA chiffre la clé AES · schéma de TLS/HTTPS",
                     font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM")).pack(side="left", padx=8)

        # Animation canvas
        self.hybrid_canvas = tk.Canvas(c, height=100, bg=T.get("BG_DEEP"),
                                        highlightthickness=1,
                                        highlightbackground=T.get("BORDER"))
        self.hybrid_canvas.grid(row=1, column=0, pady=(0, 6), sticky="ew")
        self.hybrid_canvas.bind("<Configure>", lambda e: self._draw_hybrid())

        # Chiffrement hybride
        ctk.CTkLabel(c, text="Message (taille illimitée) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(6, 0), sticky="w")
        self.hybrid_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                            border_color=T.get("BORDER"), border_width=1)
        self.hybrid_input.grid(row=3, column=0, pady=4, sticky="ew")

        hbf = ctk.CTkFrame(c, fg_color="transparent")
        hbf.grid(row=4, column=0, pady=4, sticky="w")
        _btn(hbf, "Chiffrement hybride", self._hybrid_enc_action,
             T.get("CYAN_BG"), T.get("CYAN"), T.get("CYAN_BORDER"), T.get("CYAN_HOVER"), width=180).pack(side="left", padx=3)
        _btn(hbf, "Animer", self._animate_hybrid,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), width=90).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Ciphertext hybride (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=5, column=0, pady=(6, 0), sticky="w")
        hybrid_out_frame = ctk.CTkFrame(c, fg_color="transparent")
        hybrid_out_frame.grid(row=6, column=0, pady=4, sticky="ew")
        hybrid_out_frame.grid_columnconfigure(0, weight=1)
        self.hybrid_output = TerminalBox(hybrid_out_frame, height=80)
        self.hybrid_output.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(hybrid_out_frame, text="Copier", command=lambda: self.hybrid_output.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")

        # Déchiffrement hybride séparé
        ctk.CTkLabel(c, text="Clé AES chiffrée RSA (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=7, column=0, pady=(6, 0), sticky="w")
        self.hybrid_dec_key_input = ctk.CTkTextbox(c, height=50, fg_color=T.get("BG_DEEP"),
                                                    border_color=T.get("BORDER"), border_width=1)
        self.hybrid_dec_key_input.grid(row=8, column=0, pady=4, sticky="ew")

        ctk.CTkLabel(c, text="Ciphertext AES (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=9, column=0, pady=(6, 0), sticky="w")
        self.hybrid_dec_cipher_input = ctk.CTkTextbox(c, height=50, fg_color=T.get("BG_DEEP"),
                                                      border_color=T.get("BORDER"), border_width=1)
        self.hybrid_dec_cipher_input.grid(row=10, column=0, pady=4, sticky="ew")

        dbf = ctk.CTkFrame(c, fg_color="transparent")
        dbf.grid(row=11, column=0, pady=4, sticky="w")
        _btn(dbf, "Déchiffrement hybride", self._hybrid_dec_action,
             T.get("CYAN_BG"), T.get("CYAN"), T.get("CYAN_BORDER"), T.get("CYAN_HOVER"), width=180).pack(side="left", padx=3)
        _btn(dbf, "Effacer", self._hybrid_clear,
             T.get("CYAN_BG"), T.get("CYAN"), T.get("CYAN_BORDER"), T.get("CYAN_HOVER"), width=90).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Message déchiffré :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=12, column=0, pady=(6, 0), sticky="w")
        hybrid_dec_out_frame = ctk.CTkFrame(c, fg_color="transparent")
        hybrid_dec_out_frame.grid(row=13, column=0, pady=4, sticky="ew")
        hybrid_dec_out_frame.grid_columnconfigure(0, weight=1)
        self.hybrid_dec_output = TerminalBox(hybrid_dec_out_frame, height=80)
        self.hybrid_dec_output.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn2 = ctk.CTkButton(hybrid_dec_out_frame, text="Copier", command=lambda: self.hybrid_dec_output.copy_to_clipboard(),
                                  width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                  text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn2.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")

        self.hybrid_status = StatusBar(c)
        self.hybrid_status.grid(row=14, column=0, pady=2, sticky="w")

    # ── Attack Section ────────────────────────────────────────────────

    def _attack_section(self):
        card = SectionCard(self, title="  SIMULATION D'ATTAQUE INTERACTIVE",
                           accent=T.get("RED"), cia_keys=["C"])
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            c,
            text=("Jouez le rôle de l'attaquant.\n"
                  "Étape 1 : chiffrement (interception).\n"
                  "Étape 2 : choisir l'attaque.\n"
                  "Étape 3 : déchiffrement et verdict."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        ctk.CTkLabel(c, text="Message clair (chiffré par le destinataire) :",
                     font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM")).grid(row=1, column=0, pady=(0, 4), sticky="w")
        self.sim_msg = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"), border_width=1)
        self.sim_msg.grid(row=2, column=0, pady=4, sticky="ew")

        step1_frame = ctk.CTkFrame(c, fg_color="transparent")
        step1_frame.grid(row=3, column=0, pady=4, sticky="w")
        _btn(step1_frame, "Étape 1 : Chiffrer (interception)", self._sim_step1,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), width=220, height=34).pack(side="left", padx=3)

        attack_frame = ctk.CTkFrame(c, fg_color="transparent")
        attack_frame.grid(row=4, column=0, pady=4, sticky="w")

        ctk.CTkLabel(attack_frame, text="Type d'attaque :", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM")).pack(side="left", padx=(0,4))
        self.sim_attack_menu = ctk.CTkOptionMenu(attack_frame,
            values=[
                "Mauvaise clé (1 bit)",
                "Corruption ciphertext",
                "Replay",
                "IV reuse (même IV)",
                "Bit flipping"
            ],
            width=180,
            fg_color=T.get("BG_HOVER"),
            button_color=T.get("RED_BORDER"),
            button_hover_color=T.get("RED_HOVER"),
            text_color=T.get("TEXT_DIM"),
            font=ctk.CTkFont(size=12),
        )
        self.sim_attack_menu.set("Mauvaise clé (1 bit)")
        self.sim_attack_menu.pack(side="left", padx=3)

        ToolTipButton(attack_frame, "Attaque",
                      custom_text=("Mauvaise clé : décryptage avec clé incorrecte.\n"
                                   "Corruption : ciphertext altéré, décryptage incorrect.\n"
                                   "Replay : réutilisation d'un ciphertext valide.\n"
                                   "IV reuse : revente du même IV (faillite du non-répétabilité).\n"
                                   "Bit flipping : altère le message de façon ciblée." )
                      ).pack(side="left", padx=8)

        _btn(attack_frame, "Étape 2 : Lancer l'attaque", self._sim_step2,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), width=220, height=34).pack(side="left", padx=3)

        action_frame = ctk.CTkFrame(c, fg_color="transparent")
        action_frame.grid(row=5, column=0, pady=4, sticky="w")
        _btn(action_frame, "Étape 3 : Déchiffrer après attaque", self._sim_step3,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), width=220, height=34).pack(side="left", padx=3)
        _btn(action_frame, "Réinitialiser simulation", self._sim_reset,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), width=180, height=34).pack(side="left", padx=3)

        self.sim_info = ctk.CTkLabel(c, text="Statut : en attente...", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM"))
        self.sim_info.grid(row=6, column=0, pady=(0, 4), sticky="w")

        ctk.CTkLabel(c, text="Résultat de la simulation :", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM")).grid(row=7, column=0, pady=(0, 0), sticky="w")
        log_frame = ctk.CTkFrame(c, fg_color="transparent")
        log_frame.grid(row=8, column=0, pady=4, sticky="ew")
        log_frame.grid_columnconfigure(0, weight=1)

        self.attack_log = TerminalBox(log_frame, height=140)
        self.attack_log.grid(row=0, column=0, pady=0, sticky="ew")
        ctk.CTkButton(log_frame, text="Copier", command=lambda: self.attack_log.copy_to_clipboard(),
                      width=80, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                      text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER")).grid(row=0, column=1, padx=(6,0), sticky="e")

        self.attack_status = StatusBar(c)
        self.attack_status.grid(row=9, column=0, pady=2, sticky="w")

        self._sim_reset()

    # ── Hybrid canvas ─────────────────────────────────────────────────

    STEPS = [
        (0.07, "MESSAGE\nOriginal",      T.get("CYAN"),   T.get("C_CYAN_FILL"),   T.get("C_CYAN_OUTLINE")),
        (0.27, "AES-256\nChiffre data",  T.get("BLUE"),   T.get("C_BLUE_FILL"),   T.get("C_BLUE_OUTLINE")),
        (0.50, "Clé AES\nchiffrée RSA",  T.get("PURPLE"), T.get("C_PURPLE_FILL"), T.get("C_PURPLE_OUTLINE")),
        (0.73, "ENVOI\nCipher+Key",      T.get("GREEN"),  T.get("C_GREEN_FILL"),  T.get("C_GREEN_OUTLINE")),
        (0.93, "Destinat.\nDéchiffre",   T.get("CYAN"),   T.get("C_CYAN_FILL"),   T.get("C_CYAN_OUTLINE")),
    ]

    def _draw_hybrid(self, highlight: int = -1):
        cv = self.hybrid_canvas
        cv.delete("all")
        self.update_idletasks()
        W = cv.winfo_width() or 720
        bw, bh, yc = 98, 46, 55

        for i, (frac, label, color, fill, outline) in enumerate(self.STEPS):
            x  = int(W * frac)
            bg = fill if i != highlight else color  # solid highlight
            oc = color
            lw = 2 if i == highlight else 1
            cv.create_rectangle(x - bw//2, yc - bh//2, x + bw//2, yc + bh//2,
                                  fill=bg, outline=oc, width=lw)
            for j, line in enumerate(label.split("\n")):
                cv.create_text(x, yc - 7 + j * 16, text=line,
                                fill=color, font=("Courier", 9, "bold"))

        # Arrows
        xs = [int(W * f) for f, *_ in self.STEPS]
        for a, b in zip(xs, xs[1:]):
            cv.create_line(a + bw//2 + 2, yc, b - bw//2 - 2, yc,
                            fill=T.get("TEXT_DIM"), width=1, arrow=tk.LAST)

    def _animate_hybrid(self, step: int = 0):
        self._draw_hybrid(highlight=step)
        if step < len(self.STEPS) - 1:
            self.after(650, lambda: self._animate_hybrid(step + 1))

    # ── AES handlers ──────────────────────────────────────────────────

    def _aes_gen(self):
        k = self.sym.generate_key()
        self._aes_key = k
        self.aes_key_entry.delete(0, "end")
        self.aes_key_entry.insert(0, self.sym.key_to_hex(k))
        self.aes_status.set("Clé AES-256 générée (32 octets / 256 bits)", "ok")

    def _aes_import(self):
        path = filedialog.askopenfilename(title="Importer clé AES (fichier hex .txt)")
        if not path: return
        try:
            k = self.sym.key_from_hex(open(path).read().strip())
            self._aes_key = k
            self.aes_key_entry.delete(0, "end")
            self.aes_key_entry.insert(0, self.sym.key_to_hex(k))
            self.aes_status.set("Clé AES importée.", "ok")
        except Exception as e:
            self.aes_status.set(str(e), "error")

    def _aes_export(self):
        if not self._aes_key:
            self.aes_status.set("Générez d'abord une clé.", "warning"); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             initialfile="aes_key.txt")
        if not path: return
        open(path, "w").write(self.sym.key_to_hex(self._aes_key))
        self.aes_status.set(f"Clé exportée → {path}", "ok")

    def _get_aes_key(self):
        h = self.aes_key_entry.get().strip()
        if not h: raise ValueError("Clé AES manquante.")
        return self.sym.key_from_hex(h)

    def _aes_enc(self):
        try:
            key  = self._get_aes_key()
            text = self.aes_input.get("0.0", "end").strip()
            if not text: raise ValueError("Texte vide.")
            ct = self.sym.encrypt_text(text, key)
            self.aes_output.set_text(ct.hex())
            self.aes_status.set(f"Chiffré ({len(ct)} octets). IV={ct[:16].hex()[:16]}...", "ok")
        except Exception as e:
            self.aes_status.set(str(e), "error")

    def _aes_dec(self):
        try:
            key = self._get_aes_key()
            h   = self.aes_dec_input.get("0.0", "end").strip()
            if not h: raise ValueError("Aucun ciphertext.")
            pt = self.sym.decrypt_text(bytes.fromhex(h), key)
            self.aes_dec_output.set_text(pt)
            self.aes_status.set("Déchiffrement AES réussi.", "ok")
        except Exception as e:
            self.aes_status.set(str(e), "error")

    def _aes_enc_file(self):
        try:
            key = self._get_aes_key()
            src = filedialog.askopenfilename()
            if not src: return
            self.sym.encrypt_file(src, src + ".enc", key)
            self.aes_status.set(f"Fichier chiffré → {src}.enc", "ok")
        except Exception as e:
            self.aes_status.set(str(e), "error")

    def _aes_dec_file(self):
        try:
            key = self._get_aes_key()
            src = filedialog.askopenfilename()
            if not src: return
            self.sym.decrypt_file(src, src.replace(".enc", ".dec"), key)
            self.aes_status.set(f"Déchiffré → {src.replace('.enc','.dec')}", "ok")
        except Exception as e:
            self.aes_status.set(str(e), "error")

    def _aes_clear(self):
        self.aes_input.delete("0.0", "end")
        self.aes_output.clear()
        self.aes_dec_input.delete("0.0", "end")
        self.aes_dec_output.clear()
        self.aes_status.clear()

    # ── RSA handlers ──────────────────────────────────────────────────

    def _rsa_gen(self):
        self.rsa_key_status.set("Génération RSA-2048...", "loading"); self.update()
        self._rsa_priv, self._rsa_pub = self.asym.generate_key_pair(2048)
        self.asym.save_keys(self._rsa_priv, self._rsa_pub, "keys")
        self.rsa_key_status.set("Paire RSA-2048 générée → keys/", "ok")

    def _rsa_import_priv(self):
        path = filedialog.askopenfilename(title="Clé privée RSA (.pem)")
        if not path: return
        try:
            pem = open(path, "rb").read()
            self._rsa_priv = self.asym.private_key_from_pem(pem)
            self._rsa_pub  = self._rsa_priv.public_key()
            self.rsa_key_status.set(f"Clé privée importée.", "ok")
        except Exception as e:
            self.rsa_key_status.set(str(e), "error")

    def _rsa_export(self):
        if not self._rsa_priv:
            self.rsa_key_status.set("Aucune clé à exporter.", "warning"); return
        self.asym.save_keys(self._rsa_priv, self._rsa_pub, "keys")
        self.rsa_key_status.set("Clés exportées → keys/", "ok")

    def _rsa_enc(self):
        try:
            if not self._rsa_pub: raise ValueError("Générez ou importez une paire RSA.")
            text = self.rsa_input.get("0.0", "end").strip()
            if not text: raise ValueError("Texte vide.")
            ct = self.asym.encrypt(text.encode(), self._rsa_pub)
            self.rsa_output.set_text(ct.hex())
            self.rsa_status.set(f"Chiffré RSA ({len(ct)} octets).", "ok")
        except Exception as e:
            self.rsa_status.set(str(e), "error")

    def _rsa_dec(self):
        try:
            if not self._rsa_priv: raise ValueError("Aucune clé privée.")
            h = self.rsa_dec_input.get("0.0", "end").strip()
            if not h: raise ValueError("Aucun ciphertext.")
            pt = self.asym.decrypt(bytes.fromhex(h), self._rsa_priv)
            self.rsa_dec_output.set_text(pt.decode())
            self.rsa_status.set("Déchiffrement RSA réussi.", "ok")
        except Exception as e:
            self.rsa_status.set(str(e), "error")

    def _rsa_enc_file(self):
        try:
            if not self._rsa_pub: raise ValueError("Générez ou importez une paire RSA.")
            src = filedialog.askopenfilename()
            if not src: return
            with open(src, "rb") as f:
                plaintext = f.read()
            if len(plaintext) > 190:
                raise ValueError(f"Fichier trop volumineux: {len(plaintext)} > 190 octets.")
            ct = self.asym.encrypt(plaintext, self._rsa_pub)
            self.rsa_output.set_text(ct.hex())
            self.rsa_status.set(f"Fichier chiffré RSA ({len(ct)} octets).", "ok")
        except Exception as e:
            self.rsa_status.set(str(e), "error")

    def _rsa_dec_file(self):
        try:
            if not self._rsa_priv: raise ValueError("Aucune clé privée.")
            h = self.rsa_dec_input.get("0.0", "end").strip()
            if not h: raise ValueError("Aucun ciphertext.")
            plaintext = self.asym.decrypt(bytes.fromhex(h), self._rsa_priv)
            path = filedialog.asksaveasfilename(defaultextension=".dec")
            if not path: return
            with open(path, "wb") as f:
                f.write(plaintext)
            self.rsa_dec_output.set_text(plaintext.decode('utf-8', errors='replace')[:100] + "...")
            self.rsa_status.set(f"Fichier déchiffré → {path}", "ok")
        except Exception as e:
            self.rsa_status.set(str(e), "error")

    def _rsa_clear(self):
        self.rsa_input.delete("0.0", "end")
        self.rsa_output.clear()
        self.rsa_dec_input.delete("0.0", "end")
        self.rsa_dec_output.clear()
        self.rsa_status.clear()

    # ── Hybrid handlers ───────────────────────────────────────────────

    def _hybrid_enc_action(self):
        try:
            if not self._rsa_pub: raise ValueError("Générez une paire RSA d'abord.")
            text = self.hybrid_input.get("0.0", "end").strip()
            if not text: raise ValueError("Message vide.")
            self._hybrid_enc = self.asym.hybrid_encrypt(text, self._rsa_pub)
            out = (f"[Clé AES chiffrée RSA]\n"
                   f"{self._hybrid_enc['encrypted_aes_key'].hex()}\n\n"
                   f"[Ciphertext AES]\n{self._hybrid_enc['ciphertext'].hex()}")
            self.hybrid_output.set_text(out)
            self.hybrid_status.set("Chiffrement hybride réussi.", "ok")
            self._animate_hybrid()
        except Exception as e:
            self.hybrid_status.set(str(e), "error")

    def _hybrid_dec_action(self):
        try:
            if not self._rsa_priv: raise ValueError("Aucune clé privée RSA.")
            key_hex = self.hybrid_dec_key_input.get("0.0", "end").strip()
            cipher_hex = self.hybrid_dec_cipher_input.get("0.0", "end").strip()
            if not key_hex: raise ValueError("Clé AES chiffrée manquante.")
            if not cipher_hex: raise ValueError("Ciphertext AES manquant.")
            pt = self.asym.hybrid_decrypt(
                bytes.fromhex(key_hex),
                bytes.fromhex(cipher_hex),
                self._rsa_priv)
            self.hybrid_dec_output.set_text(pt)
            self.hybrid_status.set("Déchiffrement hybride réussi.", "ok")
        except Exception as e:
            self.hybrid_status.set(str(e), "error")

    def _hybrid_clear(self):
        self.hybrid_input.delete("0.0", "end")
        self.hybrid_output.clear()
        self.hybrid_dec_key_input.delete("0.0", "end")
        self.hybrid_dec_cipher_input.delete("0.0", "end")
        self.hybrid_dec_output.clear()
        self.hybrid_status.clear()
        self._hybrid_enc = None

    # ── Attack simulation / interactive flow ───────────────────────────

    def _set_sim_info(self, text, level="info"):
        color = T.get("TEXT_DIM")
        if level == "ok":
            color = T.get("GREEN")
        elif level == "error":
            color = T.get("RED")
        elif level == "warning":
            color = T.get("AMBER")
        self.sim_info.configure(text=f"Statut : {text}", text_color=color)

    def _sim_reset(self):
        self._sim_step = 0
        self._sim_plain = ""
        self._sim_key = None
        self._sim_cipher = None
        self._sim_cipher_attacked = None
        self._sim_attack_mode = None
        self._sim_attacker_key = None
        self.sim_msg.delete("0.0", "end")
        self.attack_log.clear()
        self.sim_info.configure(text="Statut : en attente...", text_color=T.get("TEXT_DIM"))
        self.attack_status.clear()

    def _sim_step1(self):
        try:
            self._sim_plain = self.sim_msg.get("0.0", "end").strip()
            if not self._sim_plain:
                raise ValueError("Saisissez un message clair avant de lancer l'étape 1.")

            self._sim_key = self.sym.generate_key()
            self._sim_cipher = self.sym.encrypt_text(self._sim_plain, self._sim_key)
            iv = self._sim_cipher[:self.sym.IV_SIZE]
            ct_only = self._sim_cipher[self.sym.IV_SIZE:]
            nb_blocs = len(ct_only) // 16
            self._sim_step = 1
            self._sim_attack_mode = None
            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                "║  ÉTAPE 1 — Le destinataire chiffre. Vous interceptez.   ║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                f"[PLAINTEXT intercepté]  {self._sim_plain!r}\n"
                f"[Longueur]              {len(self._sim_plain)} caractères → "
                f"{len(ct_only)} octets chiffrés ({nb_blocs} bloc(s) AES de 16 oct.)\n\n"
                f"[IV  (16 oct, public)]  {iv.hex()}\n"
                f"[Clé AES (256 bits)]    {self._sim_key.hex()}\n"
                f"  ↑ Cette clé ne voyage JAMAIS sur le réseau en clair.\n\n"
                f"[Ciphertext total]      {self._sim_cipher.hex()}\n"
                f"  Structure : IV(32 chars hex) + CT({len(ct_only)*2} chars hex)\n\n"
                "→ En tant qu'attaquant, vous voyez le ciphertext mais PAS la clé.\n"
                "→ Choisissez maintenant une attaque et cliquez Étape 2."
            )
            self._set_sim_info("Étape 1 terminée — interception réussie. Choisir une attaque.", "ok")
            self.attack_status.set("Ciphertext intercepté. Choisissez une attaque.", "info")
        except Exception as e:
            self._set_sim_info(str(e), "error")
            self.attack_status.set(str(e), "error")

    def _sim_step2(self):
        try:
            if self._sim_step < 1 or not self._sim_cipher:
                raise ValueError("Exécutez d'abord l'étape 1 pour générer ciphertext et clé.")

            mode = self.sim_attack_menu.get()
            self._sim_attack_mode = mode
            iv = self._sim_cipher[:self.sym.IV_SIZE]

            if mode == "Mauvaise clé (1 bit)":
                # Flip bit 0 du premier octet
                bad_key_bytes = bytearray(self._sim_key)
                bad_key_bytes[0] ^= 0x01
                self._sim_attacker_key = bytes(bad_key_bytes)
                self._sim_cipher_attacked = self._sim_cipher
                diff_pos = 0
                explanation = (
                    "TECHNIQUE : AES est une permutation bijective sur 128 bits.\n"
                    "Modifier 1 seul bit dans la clé de 256 bits produit un\n"
                    "décryptage totalement différent — aucun lien avec le plaintext.\n\n"
                    f"Clé correcte  : {self._sim_key.hex()}\n"
                    f"Clé attaquant : {self._sim_attacker_key.hex()}\n"
                    f"Bit modifié   : bit 0 de l'octet 0\n\n"
                    "RÉSULTAT ATTENDU → échec total du déchiffrement (garbage ou erreur padding)."
                )

            elif mode == "Corruption ciphertext":
                bad = bytearray(self._sim_cipher)
                if len(bad) <= self.sym.IV_SIZE + 16:
                    raise ValueError("Message trop court : ajoutez au moins 2 blocs.")
                # Corrompt octet 17 = début du 2ème bloc CT
                target_byte = self.sym.IV_SIZE
                original_byte = bad[target_byte]
                bad[target_byte] ^= 0xFF  # flip tous les bits de cet octet
                self._sim_cipher_attacked = bytes(bad)
                self._sim_attacker_key = self._sim_key
                explanation = (
                    "TECHNIQUE CBC : corrompre 1 octet dans le bloc N produit :\n"
                    "  • Bloc N    → entièrement illisible (16 octets garbage)\n"
                    "  • Bloc N+1  → 1 seul octet corrompu (propagation partielle)\n\n"
                    f"Octet corrompu    : position {target_byte} (début bloc 1)\n"
                    f"Valeur originale  : 0x{original_byte:02X}\n"
                    f"Valeur après XOR  : 0x{original_byte ^ 0xFF:02X}\n\n"
                    "RÉSULTAT ATTENDU → erreur de padding (InvalidPadding) car le\n"
                    "dernier octet du plaintext est compromis si c'était le dernier bloc."
                )

            elif mode == "Replay":
                self._sim_cipher_attacked = self._sim_cipher
                self._sim_attacker_key = self._sim_key
                explanation = (
                    "TECHNIQUE : L'attaquant réutilise le ciphertext valide intercepté.\n"
                    "Sans mécanisme anti-replay (nonce, timestamp, numéro de séquence),\n"
                    "le serveur accepte ce message comme authentique.\n\n"
                    "Ciphertext rejoué : identique à l'original\n"
                    f"  {self._sim_cipher.hex()[:64]}...\n\n"
                    "RÉSULTAT ATTENDU → déchiffrement RÉUSSI !\n"
                    "→ C'est la faille : le destinataire ne peut pas distinguer\n"
                    "  un replay d'un vrai message sans timestamp/HMAC."
                )

            elif mode == "IV reuse (même IV)":
                # Cas réaliste : 2 plaintexts différents chiffrés avec même IV+clé
                # On peut XOR les deux ciphertexts pour obtenir XOR des plaintexts
                plain2 = "TRANSFERT 9999€ → Attaquant"
                plain2_bytes = plain2.encode("utf-8")
                padded2 = self.sym._pad(plain2_bytes)
                cipher2_obj = self.sym._build_cipher(self._sim_key, iv)
                enc2 = cipher2_obj.encryptor()
                ct2 = enc2.update(padded2) + enc2.finalize()
                cipher2_full = iv + ct2

                # XOR des deux ciphertexts = XOR des plaintexts (premier bloc)
                ct1 = self._sim_cipher[self.sym.IV_SIZE:]
                xored = bytes(a ^ b for a, b in zip(ct1[:16], ct2[:16]))

                self._sim_cipher_attacked = cipher2_full
                self._sim_attacker_key = self._sim_key
                self._sim_iv_reuse_plain2 = plain2
                self._sim_iv_reuse_xor = xored

                p1_bytes = self._sim_plain.encode("utf-8")
                plain_xor = bytes(a ^ b for a, b in zip(p1_bytes[:16], plain2_bytes[:16]))

                explanation = (
                    "TECHNIQUE : Si IV est réutilisé avec même clé pour 2 messages :\n"
                    "  CT1 = AES_CBC(K, IV, P1)  →  CT1[0] = AES(K,IV) XOR P1[0:16]\n"
                    "  CT2 = AES_CBC(K, IV, P2)  →  CT2[0] = AES(K,IV) XOR P2[0:16]\n"
                    "  Donc : CT1[0] XOR CT2[0] = P1[0:16] XOR P2[0:16]\n\n"
                    f"Message 1 (bloc 0) : {self._sim_plain[:16]!r}\n"
                    f"Message 2 (bloc 0) : {plain2[:16]!r}\n"
                    f"XOR plaintexts     : {plain_xor.hex()}\n"
                    f"XOR ciphertexts    : {xored.hex()}\n"
                    "→ Si l'attaquant connaît P1, il retrouve P2 entièrement !\n\n"
                    "RÉSULTAT ATTENDU → le message 2 se déchiffre normalement.\n"
                    "La fuite est cryptanalytique, pas une erreur de déchiffrement."
                )

            elif mode == "Bit flipping":
                # Bit flipping sur l'IV : flip bit dans IV → flip même bit dans bloc 1 du plaintext
                bad = bytearray(self._sim_cipher)
                target_iv_byte = 0  # premier octet de l'IV
                original_iv = bad[target_iv_byte]
                bad[target_iv_byte] ^= 0x01   # flip 1 bit
                self._sim_cipher_attacked = bytes(bad)
                self._sim_attacker_key = self._sim_key

                # Calculer le plaintext attendu après flip
                plain_bytes = bytearray(self._sim_plain.encode("utf-8"))
                if plain_bytes:
                    expected_first_byte = plain_bytes[0] ^ 0x01
                    expected_char = chr(expected_first_byte) if expected_first_byte < 128 else "?"
                else:
                    expected_char = "?"

                explanation = (
                    "TECHNIQUE (attaque CBC réelle) :\n"
                    "En mode CBC : Plaintext[i] = AES_decrypt(CT[i]) XOR CT[i-1]\n"
                    "Pour le 1er bloc : Plaintext[0] = AES_decrypt(CT[0]) XOR IV\n\n"
                    "→ Modifier IV[j] flip exactement Plaintext[0][j] !\n"
                    "   Aucun autre octet n'est affecté dans le bloc 1.\n\n"
                    f"IV octet[0] original : 0x{original_iv:02X}  ({original_iv:08b}b)\n"
                    f"IV octet[0] modifié  : 0x{original_iv ^ 0x01:02X}  ({original_iv ^ 0x01:08b}b)\n"
                    f"Plaintext[0] original: {chr(plain_bytes[0]) if plain_bytes else '?'!r}\n"
                    f"Plaintext[0] attendu : {expected_char!r} (bit 0 flippé)\n\n"
                    "RÉSULTAT ATTENDU → déchiffrement RÉUSSIT mais 1er caractère corrompu.\n"
                    "Cas réel : un attaquant peut forger 'admin=true' depuis 'admin=false'."
                )
            else:
                raise ValueError("Type d'attaque non supporté.")

            self._sim_step = 2
            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                f"║  ÉTAPE 2 — Attaque : {mode:<36}║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                f"{explanation}\n\n"
                f"[Ciphertext envoyé au destinataire]\n"
                f"{self._sim_cipher_attacked.hex()[:80]}..."
            )
            self._set_sim_info("Étape 2 terminée — attaque préparée. Cliquez Étape 3.", "ok")
            self.attack_status.set("Attaque construite. Passez à l'étape 3.", "info")
        except Exception as e:
            self._set_sim_info(str(e), "error")
            self.attack_status.set(str(e), "error")

    def _sim_step3(self):
        try:
            if self._sim_step < 2:
                raise ValueError("Exécutez d'abord l'étape 2 avant de déchiffrer.")

            mode = self._sim_attack_mode
            ct = self._sim_cipher_attacked

            if mode == "Mauvaise clé (1 bit)":
                key = self._sim_attacker_key
            else:
                key = self._sim_key

            # Tentative de déchiffrement
            try:
                decrypted = self.sym.decrypt_text(ct, key)
                dec_success = True
            except Exception as dec_err:
                decrypted = None
                dec_success = False
                dec_error = str(dec_err)

            # Déchiffrement avec la vraie clé pour comparer
            try:
                original_dec = self.sym.decrypt_text(self._sim_cipher, self._sim_key)
            except Exception:
                original_dec = self._sim_plain

            # Construire le verdict selon l'attaque
            if mode == "Mauvaise clé (1 bit)":
                if dec_success:
                    verdict = "⚠️  INATTENDU : déchiffrement réussi avec mauvaise clé !"
                    analysis = "Cela indiquerait une faille grave — ne devrait pas arriver avec AES."
                    ok = False
                else:
                    verdict = "✅  ATTENDU : AES bloque — 1 bit de différence = échec total"
                    analysis = (
                        f"Résultat obtenu     : ERREUR (padding invalide / données corrompues)\n"
                        f"Texte original      : {self._sim_plain!r}\n"
                        f"Conclusion          : AES-256 est sûr — brute-force de la clé = 2^256 essais\n"
                        f"Temps brute-force   : ~10^57 ans avec tous les ordinateurs actuels"
                    )
                    ok = True

            elif mode == "Corruption ciphertext":
                if dec_success:
                    verdict = "⚠️  Déchiffrement partiel (corruption en milieu de message)"
                    analysis = (
                        f"Plaintext récupéré  : {decrypted!r}\n"
                        f"Plaintext original  : {original_dec!r}\n"
                        f"Différence          : bloc 1 entièrement corrompu, reste intact\n"
                        f"Leçon               : Utilisez AES-GCM (authentifié) — détecte la corruption."
                    )
                    ok = False
                else:
                    verdict = "✅  ATTENDU : erreur de padding détectée"
                    analysis = (
                        f"Erreur              : {dec_error}\n"
                        f"Explication         : Le dernier bloc corrompé produit un padding invalide.\n"
                        f"Leçon               : Sans MAC/AEAD, la corruption n'est pas toujours détectée."
                    )
                    ok = True

            elif mode == "Replay":
                if dec_success:
                    verdict = "⚠️  FAILLE EXPOSÉE : Replay attack réussie !"
                    analysis = (
                        f"Texte déchiffré     : {decrypted!r}\n"
                        f"Texte original      : {self._sim_plain!r}\n\n"
                        f"Le destinataire accepte le message comme légitime.\n"
                        f"MITIGATION : Ajouter un HMAC + timestamp + nonce unique par message.\n"
                        f"Protocoles : TLS utilise des numéros de séquence pour éviter cela."
                    )
                    ok = False
                else:
                    verdict = "Replay échoué (inhabituel)"
                    analysis = f"Erreur : {dec_error}"
                    ok = True

            elif mode == "IV reuse (même IV)":
                if dec_success:
                    verdict = "⚠️  Les 2 messages se déchiffrent — la fuite est cryptanalytique"
                    plain2 = getattr(self, '_sim_iv_reuse_plain2', 'message 2')
                    xored = getattr(self, '_sim_iv_reuse_xor', b'')
                    analysis = (
                        f"Message 2 déchiffré : {decrypted!r}\n"
                        f"Message 1 original  : {self._sim_plain!r}\n\n"
                        f"XOR CT1⊕CT2 (bloc0) : {xored.hex()}\n"
                        f"Si attaquant connaît P1, il peut calculer P2 = XOR(CT1⊕CT2, P1)\n\n"
                        f"MITIGATION : Toujours générer un IV aléatoire pour chaque chiffrement.\n"
                        f"L'IV AES-CBC doit être UNIQUE et IMPRÉVISIBLE."
                    )
                    ok = False
                else:
                    verdict = f"Erreur inattendue : {dec_error}"
                    analysis = ""
                    ok = True

            elif mode == "Bit flipping":
                if dec_success:
                    verdict = "⚠️  BIT FLIPPING RÉUSSI — plaintext modifié chirurgicalement !"
                    orig_bytes = self._sim_plain.encode("utf-8")
                    dec_bytes = decrypted.encode("utf-8") if decrypted else b""
                    diffs = [(i, orig_bytes[i:i+1], dec_bytes[i:i+1])
                             for i in range(min(len(orig_bytes), len(dec_bytes)))
                             if i < len(orig_bytes) and i < len(dec_bytes) and orig_bytes[i] != dec_bytes[i]]
                    diff_str = "\n".join(f"  Position {i}: {o!r} → {d!r}" for i, o, d in diffs[:5])
                    analysis = (
                        f"Plaintext original  : {self._sim_plain!r}\n"
                        f"Plaintext déchiffré : {decrypted!r}\n\n"
                        f"Octets modifiés :\n{diff_str if diff_str else '  (aucun visible)'}\n\n"
                        f"IMPACT RÉEL : Un attaquant peut forger des champs précis\n"
                        f"  ex: 'montant=0100€' → 'montant=9999€'\n"
                        f"MITIGATION : AES-GCM (AEAD) détecte toute modification."
                    )
                    ok = False
                else:
                    verdict = f"Erreur padding (IV flip a corrompu le padding)"
                    analysis = f"Erreur : {dec_error}\nEssayez avec un message plus long (plusieurs blocs)."
                    ok = True
            else:
                verdict = "Mode inconnu"
                analysis = ""
                ok = False

            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                f"║  ÉTAPE 3 — VERDICT : {mode:<35}║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                f"{verdict}\n\n"
                f"{analysis}"
            )

            if ok:
                self._set_sim_info("Simulation terminée — la défense a tenu.", "ok")
                self.attack_status.set("✅ Attaque bloquée par AES-256.", "ok")
            else:
                self._set_sim_info("Simulation terminée — FAILLE DÉMONTRÉE.", "warning")
                self.attack_status.set("⚠️  Attaque réussie — voir analyse dans le log.", "warning")

            self._sim_step = 3
        except Exception as e:
            self._set_sim_info(str(e), "error")
            self.attack_status.set(str(e), "error")

