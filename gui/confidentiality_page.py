"""
Module: confidentiality_page.py
Role:   GUI page for AES, RSA, and Hybrid encryption/decryption
        Calls core.symmetric and core.asymmetric — zero crypto code here
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from core.symmetric  import SymmetricCipher
from core.asymmetric import AsymmetricCipher


class ConfidentialityPage(ctk.CTkFrame):
    """
    Confidentiality page — AES-256-CBC, RSA-2048, Hybrid encryption.

    CIA Objective : Confidentiality
    """

    INFO_TEXT = (
        "🔒  CONFIDENTIALITÉ\n\n"
        "Objectif CIA : Garantir que seul le destinataire autorisé peut lire le message.\n\n"
        "• AES-256-CBC (symétrique) : Rapide, idéal pour les grandes données.\n"
        "  Limite : la clé doit être partagée secrètement entre les parties.\n\n"
        "• RSA-2048 (asymétrique) : Clé publique pour chiffrer, privée pour déchiffrer.\n"
        "  Limite : Lent, limité à ~190 octets de données directes.\n\n"
        "• Hybride : RSA chiffre la clé AES → meilleur des deux mondes.\n"
        "  C'est le schéma utilisé dans TLS/HTTPS."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.sym  = SymmetricCipher()
        self.asym = AsymmetricCipher()

        # State
        self._aes_key    = None
        self._rsa_priv   = None
        self._rsa_pub    = None
        self._hybrid_enc = None   # dict from hybrid_encrypt

        self._build_info_banner()
        self._build_tabs()

    # ── Info banner ──────────────────────────────────────────────────

    def _build_info_banner(self):
        banner = ctk.CTkTextbox(self, height=155, wrap="word", font=ctk.CTkFont(size=12))
        banner.insert("0.0", self.INFO_TEXT)
        banner.configure(state="disabled")
        banner.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")

    # ── Tabs ─────────────────────────────────────────────────────────

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")

        self.tabs.add("🔑  AES Symétrique")
        self.tabs.add("🔐  RSA Asymétrique")
        self.tabs.add("⚡  Hybride")

        self._build_aes_tab(self.tabs.tab("🔑  AES Symétrique"))
        self._build_rsa_tab(self.tabs.tab("🔐  RSA Asymétrique"))
        self._build_hybrid_tab(self.tabs.tab("⚡  Hybride"))

    # ── AES Tab ──────────────────────────────────────────────────────

    def _build_aes_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        # Key section
        key_frame = ctk.CTkFrame(parent)
        key_frame.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        key_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(key_frame, text="Clé AES (hex) :", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=10, pady=8, sticky="w")

        self.aes_key_entry = ctk.CTkEntry(key_frame, placeholder_text="Générez ou collez une clé hex 256-bit")
        self.aes_key_entry.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ctk.CTkButton(key_frame, text="Générer clé", width=120, command=self._aes_generate_key).grid(
            row=0, column=2, padx=8, pady=8)

        # Input
        ctk.CTkLabel(parent, text="Texte à chiffrer :").grid(row=1, column=0, padx=8, pady=(8,0), sticky="w")
        self.aes_input = ctk.CTkTextbox(parent, height=80)
        self.aes_input.grid(row=2, column=0, padx=8, pady=4, sticky="ew")

        # Buttons
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=3, column=0, padx=8, pady=4, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔒 Chiffrer", command=self._aes_encrypt).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="🔓 Déchiffrer", command=self._aes_decrypt).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="📂 Chiffrer fichier", command=self._aes_encrypt_file).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="📂 Déchiffrer fichier", command=self._aes_decrypt_file).pack(side="left", padx=4)

        # Output
        ctk.CTkLabel(parent, text="Résultat (hex) :").grid(row=4, column=0, padx=8, pady=(8,0), sticky="w")
        self.aes_output = ctk.CTkTextbox(parent, height=80)
        self.aes_output.grid(row=5, column=0, padx=8, pady=4, sticky="ew")

        # Status
        self.aes_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.aes_status.grid(row=6, column=0, padx=8, pady=4, sticky="w")

    # ── RSA Tab ──────────────────────────────────────────────────────

    def _build_rsa_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(parent, text="🔑 Générer paire RSA-2048", command=self._rsa_generate_keys).grid(
            row=0, column=0, padx=8, pady=8, sticky="w")

        self.rsa_key_status = ctk.CTkLabel(parent, text="⚠️ Aucune clé générée", text_color="orange")
        self.rsa_key_status.grid(row=1, column=0, padx=8, pady=0, sticky="w")

        ctk.CTkLabel(parent, text="Texte à chiffrer (≤ 190 octets) :").grid(
            row=2, column=0, padx=8, pady=(12,0), sticky="w")
        self.rsa_input = ctk.CTkTextbox(parent, height=70)
        self.rsa_input.grid(row=3, column=0, padx=8, pady=4, sticky="ew")

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=4, column=0, padx=8, pady=4, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔒 Chiffrer (clé publique)", command=self._rsa_encrypt).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="🔓 Déchiffrer (clé privée)", command=self._rsa_decrypt).pack(side="left", padx=4)

        ctk.CTkLabel(parent, text="Résultat (hex) :").grid(row=5, column=0, padx=8, pady=(8,0), sticky="w")
        self.rsa_output = ctk.CTkTextbox(parent, height=70)
        self.rsa_output.grid(row=6, column=0, padx=8, pady=4, sticky="ew")

        self.rsa_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.rsa_status.grid(row=7, column=0, padx=8, pady=4, sticky="w")

    # ── Hybrid Tab ───────────────────────────────────────────────────

    def _build_hybrid_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        info = ctk.CTkLabel(
            parent,
            text="Le chiffrement hybride combine AES (vitesse) + RSA (échange de clé sécurisé).",
            font=ctk.CTkFont(size=12), text_color="gray", wraplength=600
        )
        info.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        ctk.CTkButton(parent, text="🔑 Générer paire RSA (si pas déjà fait)",
                      command=self._rsa_generate_keys).grid(row=1, column=0, padx=8, pady=4, sticky="w")

        ctk.CTkLabel(parent, text="Message à chiffrer (taille illimitée) :").grid(
            row=2, column=0, padx=8, pady=(8,0), sticky="w")
        self.hybrid_input = ctk.CTkTextbox(parent, height=80)
        self.hybrid_input.grid(row=3, column=0, padx=8, pady=4, sticky="ew")

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=4, column=0, padx=8, pady=4, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔒 Chiffrement hybride", command=self._hybrid_encrypt).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="🔓 Déchiffrement hybride", command=self._hybrid_decrypt).pack(side="left", padx=4)

        ctk.CTkLabel(parent, text="Résultat :").grid(row=5, column=0, padx=8, pady=(8,0), sticky="w")
        self.hybrid_output = ctk.CTkTextbox(parent, height=100)
        self.hybrid_output.grid(row=6, column=0, padx=8, pady=4, sticky="ew")

        self.hybrid_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.hybrid_status.grid(row=7, column=0, padx=8, pady=4, sticky="w")

    # ── AES handlers ─────────────────────────────────────────────────

    def _aes_generate_key(self):
        key = self.sym.generate_key()
        self._aes_key = key
        self.aes_key_entry.delete(0, "end")
        self.aes_key_entry.insert(0, self.sym.key_to_hex(key))
        self._set_status(self.aes_status, "✅ Clé AES-256 générée avec succès.", "green")

    def _get_aes_key(self):
        hex_val = self.aes_key_entry.get().strip()
        if not hex_val:
            raise ValueError("Veuillez générer ou entrer une clé AES.")
        return self.sym.key_from_hex(hex_val)

    def _aes_encrypt(self):
        try:
            key  = self._get_aes_key()
            text = self.aes_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Veuillez entrer un texte à chiffrer.")
            ct = self.sym.encrypt_text(text, key)
            self._set_output(self.aes_output, ct.hex())
            self._set_status(self.aes_status, "✅ Chiffrement AES réussi.", "green")
        except Exception as e:
            self._set_status(self.aes_status, f"❌ {e}", "red")

    def _aes_decrypt(self):
        try:
            key     = self._get_aes_key()
            hex_val = self.aes_output.get("0.0", "end").strip()
            if not hex_val:
                raise ValueError("Aucun texte chiffré dans la zone résultat.")
            ct = bytes.fromhex(hex_val)
            pt = self.sym.decrypt_text(ct, key)
            self._set_output(self.aes_input, pt)
            self._set_status(self.aes_status, "✅ Déchiffrement AES réussi.", "green")
        except Exception as e:
            self._set_status(self.aes_status, f"❌ {e}", "red")

    def _aes_encrypt_file(self):
        try:
            key  = self._get_aes_key()
            src  = filedialog.askopenfilename(title="Fichier à chiffrer")
            if not src:
                return
            dst = src + ".enc"
            self.sym.encrypt_file(src, dst, key)
            self._set_status(self.aes_status, f"✅ Fichier chiffré → {dst}", "green")
        except Exception as e:
            self._set_status(self.aes_status, f"❌ {e}", "red")

    def _aes_decrypt_file(self):
        try:
            key = self._get_aes_key()
            src = filedialog.askopenfilename(title="Fichier chiffré (.enc)")
            if not src:
                return
            dst = src.replace(".enc", ".dec")
            self.sym.decrypt_file(src, dst, key)
            self._set_status(self.aes_status, f"✅ Fichier déchiffré → {dst}", "green")
        except Exception as e:
            self._set_status(self.aes_status, f"❌ {e}", "red")

    # ── RSA handlers ─────────────────────────────────────────────────

    def _rsa_generate_keys(self):
        self.rsa_key_status.configure(text="⏳ Génération en cours...", text_color="orange")
        self.update()
        self._rsa_priv, self._rsa_pub = self.asym.generate_key_pair(2048)
        self.asym.save_keys(self._rsa_priv, self._rsa_pub, "keys")
        self.rsa_key_status.configure(
            text="✅ Paire RSA-2048 générée et sauvegardée dans keys/",
            text_color="green"
        )

    def _rsa_encrypt(self):
        try:
            if not self._rsa_pub:
                raise ValueError("Générez d'abord une paire RSA.")
            text = self.rsa_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Veuillez entrer un texte.")
            ct = self.asym.encrypt(text.encode("utf-8"), self._rsa_pub)
            self._set_output(self.rsa_output, ct.hex())
            self._set_status(self.rsa_status, "✅ Chiffrement RSA réussi.", "green")
        except Exception as e:
            self._set_status(self.rsa_status, f"❌ {e}", "red")

    def _rsa_decrypt(self):
        try:
            if not self._rsa_priv:
                raise ValueError("Aucune clé privée RSA disponible.")
            hex_val = self.rsa_output.get("0.0", "end").strip()
            if not hex_val:
                raise ValueError("Aucun texte chiffré à déchiffrer.")
            ct = bytes.fromhex(hex_val)
            pt = self.asym.decrypt(ct, self._rsa_priv)
            self._set_output(self.rsa_input, pt.decode("utf-8"))
            self._set_status(self.rsa_status, "✅ Déchiffrement RSA réussi.", "green")
        except Exception as e:
            self._set_status(self.rsa_status, f"❌ {e}", "red")

    # ── Hybrid handlers ──────────────────────────────────────────────

    def _hybrid_encrypt(self):
        try:
            if not self._rsa_pub:
                raise ValueError("Générez d'abord une paire RSA.")
            text = self.hybrid_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Veuillez entrer un message.")
            self._hybrid_enc = self.asym.hybrid_encrypt(text, self._rsa_pub)
            display = (
                f"[Clé AES chiffrée RSA]\n{self._hybrid_enc['encrypted_aes_key'].hex()[:64]}...\n\n"
                f"[Ciphertext AES]\n{self._hybrid_enc['ciphertext'].hex()[:64]}..."
            )
            self._set_output(self.hybrid_output, display)
            self._set_status(self.hybrid_status, "✅ Chiffrement hybride réussi.", "green")
        except Exception as e:
            self._set_status(self.hybrid_status, f"❌ {e}", "red")

    def _hybrid_decrypt(self):
        try:
            if not self._rsa_priv:
                raise ValueError("Aucune clé privée RSA disponible.")
            if not self._hybrid_enc:
                raise ValueError("Chiffrez d'abord un message avec le mode hybride.")
            pt = self.asym.hybrid_decrypt(
                self._hybrid_enc["encrypted_aes_key"],
                self._hybrid_enc["ciphertext"],
                self._rsa_priv
            )
            self._set_output(self.hybrid_output, f"[Message déchiffré]\n{pt}")
            self._set_status(self.hybrid_status, "✅ Déchiffrement hybride réussi.", "green")
        except Exception as e:
            self._set_status(self.hybrid_status, f"❌ {e}", "red")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_output(widget: ctk.CTkTextbox, text: str):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)

    @staticmethod
    def _set_status(label: ctk.CTkLabel, text: str, color: str):
        label.configure(text=text, text_color=color)
