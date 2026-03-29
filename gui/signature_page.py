"""
Module: signature_page.py
Role:   GUI page for digital signature (sign + verify)
        Calls core.signature and core.asymmetric — zero crypto code here
"""

import customtkinter as ctk
from core.signature  import DigitalSignature
from core.asymmetric import AsymmetricCipher


class SignaturePage(ctk.CTkFrame):
    """
    Signature page — RSA-PSS sign with private key, verify with public key.

    CIA Objective : Authentication + Non-repudiation + Integrity
    """

    INFO_TEXT = (
        "✍️   SIGNATURE NUMÉRIQUE\n\n"
        "Objectif CIA : Authentification et Non-répudiation.\n\n"
        "• Le signataire utilise sa CLÉ PRIVÉE pour signer le condensé du message.\n"
        "• N'importe qui possédant la CLÉ PUBLIQUE peut vérifier la signature.\n"
        "• Garanties : \n"
        "  — Authentification : le message vient bien du détenteur de la clé privée.\n"
        "  — Non-répudiation : le signataire ne peut pas nier avoir signé.\n"
        "  — Intégrité       : toute modification du message invalide la signature.\n\n"
        "• Limite : La fiabilité dépend de la sécurité de la clé privée et d'une PKI de confiance."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.ds   = DigitalSignature()
        self.asym = AsymmetricCipher()

        self._priv_key  = None
        self._pub_key   = None
        self._signature = None   # bytes

        self._build_info_banner()
        self._build_tabs()

    def _build_info_banner(self):
        banner = ctk.CTkTextbox(self, height=155, wrap="word", font=ctk.CTkFont(size=12))
        banner.insert("0.0", self.INFO_TEXT)
        banner.configure(state="disabled")
        banner.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.tabs.add("🔑  Clés RSA")
        self.tabs.add("✍️   Signer")
        self.tabs.add("🔍  Vérifier")

        self._build_keys_tab(self.tabs.tab("🔑  Clés RSA"))
        self._build_sign_tab(self.tabs.tab("✍️   Signer"))
        self._build_verify_tab(self.tabs.tab("🔍  Vérifier"))

    # ── Keys tab ─────────────────────────────────────────────────────

    def _build_keys_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        desc = ctk.CTkLabel(
            parent,
            text="Générez une paire RSA-2048 dédiée à la signature. Les clés sont sauvegardées dans keys/sig_*.pem",
            font=ctk.CTkFont(size=12), text_color="gray", wraplength=620
        )
        desc.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        ctk.CTkButton(parent, text="🔑 Générer paire RSA-2048 pour signature",
                      command=self._generate_keys, height=40).grid(row=1, column=0, padx=8, pady=8, sticky="w")

        self.key_status = ctk.CTkLabel(parent, text="⚠️ Aucune clé générée", text_color="orange",
                                       font=ctk.CTkFont(size=13))
        self.key_status.grid(row=2, column=0, padx=8, pady=4, sticky="w")

        # Display PEM (read-only)
        ctk.CTkLabel(parent, text="Clé publique (PEM) :").grid(row=3, column=0, padx=8, pady=(12,0), sticky="w")
        self.pub_display = ctk.CTkTextbox(parent, height=130, font=ctk.CTkFont(family="Courier", size=10))
        self.pub_display.grid(row=4, column=0, padx=8, pady=4, sticky="ew")
        self.pub_display.configure(state="disabled")

    # ── Sign tab ─────────────────────────────────────────────────────

    def _build_sign_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(parent, text="Message à signer :").grid(row=0, column=0, padx=8, pady=(8,0), sticky="w")
        self.sign_input = ctk.CTkTextbox(parent, height=100)
        self.sign_input.grid(row=1, column=0, padx=8, pady=4, sticky="ew")

        ctk.CTkButton(parent, text="✍️  Signer avec clé privée",
                      command=self._sign_message, height=38).grid(row=2, column=0, padx=8, pady=8, sticky="w")

        ctk.CTkLabel(parent, text="Signature (hex) :").grid(row=3, column=0, padx=8, pady=(4,0), sticky="w")
        self.sign_output = ctk.CTkTextbox(parent, height=100, font=ctk.CTkFont(family="Courier", size=10))
        self.sign_output.grid(row=4, column=0, padx=8, pady=4, sticky="ew")

        self.sign_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.sign_status.grid(row=5, column=0, padx=8, pady=4, sticky="w")

    # ── Verify tab ───────────────────────────────────────────────────

    def _build_verify_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(parent, text="Message original à vérifier :").grid(
            row=0, column=0, padx=8, pady=(8,0), sticky="w")
        self.verify_msg = ctk.CTkTextbox(parent, height=80)
        self.verify_msg.grid(row=1, column=0, padx=8, pady=4, sticky="ew")

        sig_frame = ctk.CTkFrame(parent)
        sig_frame.grid(row=2, column=0, padx=8, pady=6, sticky="ew")
        sig_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(sig_frame, text="Signature (hex) :", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=10, pady=8, sticky="w")
        self.verify_sig_entry = ctk.CTkEntry(
            sig_frame,
            placeholder_text="Collez la signature hex ou utilisez 'Charger depuis onglet Signer'",
            font=ctk.CTkFont(family="Courier", size=10))
        self.verify_sig_entry.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(sig_frame, text="Charger", width=90,
                      command=self._load_sig_from_sign_tab).grid(row=0, column=2, padx=8, pady=8)

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=3, column=0, padx=8, pady=4, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔍 Vérifier signature", command=self._verify_message).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="💥 Tester message altéré", command=self._verify_tampered).pack(side="left", padx=4)

        self.verify_result = ctk.CTkTextbox(parent, height=80)
        self.verify_result.grid(row=4, column=0, padx=8, pady=4, sticky="ew")

        self.verify_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=14, weight="bold"))
        self.verify_status.grid(row=5, column=0, padx=8, pady=6, sticky="w")

    # ── Handlers ─────────────────────────────────────────────────────

    def _generate_keys(self):
        self.key_status.configure(text="⏳ Génération RSA-2048...", text_color="orange")
        self.update()
        self._priv_key, self._pub_key = self.asym.generate_key_pair(2048)

        # Save to disk
        import os
        os.makedirs("keys", exist_ok=True)
        with open("keys/sig_private.pem", "wb") as f:
            f.write(self.asym.private_key_to_pem(self._priv_key))
        pub_pem = self.asym.public_key_to_pem(self._pub_key)
        with open("keys/sig_public.pem", "wb") as f:
            f.write(pub_pem)

        # Display public key
        self.pub_display.configure(state="normal")
        self.pub_display.delete("0.0", "end")
        self.pub_display.insert("0.0", pub_pem.decode("utf-8"))
        self.pub_display.configure(state="disabled")

        self.key_status.configure(
            text="✅ Paire RSA-2048 générée → keys/sig_private.pem & sig_public.pem",
            text_color="green"
        )

    def _sign_message(self):
        try:
            if not self._priv_key:
                raise ValueError("Générez d'abord une paire RSA dans l'onglet 'Clés RSA'.")
            text = self.sign_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Veuillez entrer un message à signer.")
            self._signature = self.ds.sign_text(text, self._priv_key)
            sig_hex = self.ds.signature_to_hex(self._signature)
            self._set_textbox(self.sign_output, sig_hex)
            self._set_status(self.sign_status, f"✅ Message signé ({len(self._signature)} octets).", "green")
        except Exception as e:
            self._set_status(self.sign_status, f"❌ {e}", "red")

    def _load_sig_from_sign_tab(self):
        if not self._signature:
            return
        sig_hex = self.ds.signature_to_hex(self._signature)
        self._set_entry(self.verify_sig_entry, sig_hex)
        # Also copy message
        msg = self.sign_input.get("0.0", "end").strip()
        self._set_textbox(self.verify_msg, msg)

    def _verify_message(self):
        try:
            if not self._pub_key:
                raise ValueError("Aucune clé publique disponible. Générez une paire RSA.")
            msg = self.verify_msg.get("0.0", "end").strip()
            sig_hex = self.verify_sig_entry.get().strip()
            if not msg or not sig_hex:
                raise ValueError("Message et signature requis.")
            sig   = self.ds.signature_from_hex(sig_hex)
            valid = self.ds.verify_text(msg, sig, self._pub_key)
            result = (
                f"Message   : {msg[:60]}{'...' if len(msg)>60 else ''}\n"
                f"Résultat  : {'✅ SIGNATURE VALIDE' if valid else '❌ SIGNATURE INVALIDE'}"
            )
            self._set_textbox(self.verify_result, result)
            color = "green" if valid else "red"
            msg_s = "✅ Signature valide — authenticité et intégrité confirmées." if valid else "❌ Signature invalide — message altéré ou mauvaise clé!"
            self._set_status(self.verify_status, msg_s, color)
        except Exception as e:
            self._set_status(self.verify_status, f"❌ {e}", "red")

    def _verify_tampered(self):
        """Automatically tamper the message to demonstrate signature failure."""
        try:
            if not self._pub_key or not self._signature:
                raise ValueError("Signez d'abord un message.")
            original = self.sign_input.get("0.0", "end").strip()
            tampered = original + " [MODIFIÉ]"
            self._set_textbox(self.verify_msg, tampered)
            sig_hex = self.ds.signature_to_hex(self._signature)
            self._set_entry(self.verify_sig_entry, sig_hex)
            sig   = self._signature
            valid = self.ds.verify_text(tampered, sig, self._pub_key)
            result = (
                f"Message altéré : {tampered[:60]}\n"
                f"Résultat       : {'✅ VALIDE' if valid else '❌ INVALIDE — altération détectée!'}"
            )
            self._set_textbox(self.verify_result, result)
            self._set_status(self.verify_status, "❌ Signature invalide — altération correctement détectée!", "red")
        except Exception as e:
            self._set_status(self.verify_status, f"❌ {e}", "red")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_textbox(widget, text):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)

    @staticmethod
    def _set_entry(widget, text):
        widget.configure(state="normal")
        widget.delete(0, "end")
        widget.insert(0, text)

    @staticmethod
    def _set_status(label, text, color):
        label.configure(text=text, text_color=color)
