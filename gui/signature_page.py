import customtkinter as ctk
import os, threading, time
from tkinter import filedialog

from core.signature  import DigitalSignature
from core.asymmetric import AsymmetricCipher
import gui.theme as T

from gui.widgets import CIABadge, ToolTipButton, TerminalBox, SectionCard, StatusBar


def _btn(parent, text, cmd, fg, tc, bc, hc, width=150, height=30):
    return ctk.CTkButton(parent, text=text, command=cmd, width=width, height=height,
                          fg_color=fg, hover_color=hc, text_color=tc,
                          border_width=1, border_color=bc)


class SignaturePage(ctk.CTkScrollableFrame):

    INFO = (
        "Objectifs CIA : AUTHENTICITÉ + NON-RÉPUDIATION + INTÉGRITÉ.\n"
        "La clé PRIVÉE signe — la clé PUBLIQUE vérifie. "
        "RSA-PSS avec SHA-256 garantit qu'une modification même minime invalide la signature.\n"
        "Historique : RSA-PSS (1996) remplace PKCS1v15 — sécurité prouvable dans le modèle de l'oracle aléatoire."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color=T.get("BG_DEEP"), scrollbar_button_color=T.get("BORDER"))
        self.grid_columnconfigure(0, weight=1)
        self.ds   = DigitalSignature()
        self.asym = AsymmetricCipher()
        self._priv = None
        self._pub  = None
        self._sig  = None
        self._build()

    def _build(self):
        self._header()
        self._keys_section()
        self._sign_section()
        self._verify_section()
        self._attack_section()

    def _header(self):
        f = ctk.CTkFrame(self, fg_color=T.get("BG_CARD"), corner_radius=8,
                         border_width=1, border_color=T.get("BORDER"))
        f.grid(row=0, column=0, padx=14, pady=(14, 6), sticky="ew")
        f.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="✍️   SIGNATURE NUMÉRIQUE",
                     font=ctk.CTkFont(family="Courier", size=15, weight="bold"),
                     text_color=T.get("PURPLE")).grid(row=0, column=0, sticky="w")
        CIABadge(top, ["A", "I"]).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(f, text=self.INFO, font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"), wraplength=820, justify="left",
                     ).grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")

    def _keys_section(self):
        card = SectionCard(self, title="  Gestion des Clés RSA",
                           accent=T.get("PURPLE"), cia_keys=["A"])
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=0, column=0, pady=4, sticky="w")
        for txt, cmd in [("Générer RSA-2048", self._gen),
                          ("Importer clé privée", self._import_priv),
                          ("Importer clé publique", self._import_pub),
                          ("Exporter clés", self._export)]:
            _btn(bf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 160, 30).pack(side="left", padx=3)
        ToolTipButton(bf, "PSS").pack(side="left", padx=4)
        ToolTipButton(bf, "signature").pack(side="left", padx=2)

        self.key_status = StatusBar(c)
        self.key_status.set("Aucune clé chargée", "warning")
        self.key_status.grid(row=1, column=0, pady=4, sticky="w")

        ctk.CTkLabel(c, text="Clé publique (PEM) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(8, 0), sticky="w")
        self.pub_display = TerminalBox(c, height=110)
        pub_frame = ctk.CTkFrame(c, fg_color="transparent")
        pub_frame.grid(row=3, column=0, pady=4, sticky="ew")
        pub_frame.grid_columnconfigure(0, weight=1)
        self.pub_display = TerminalBox(pub_frame, height=110)
        self.pub_display.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(pub_frame, text="Copier", command=lambda: self.pub_display.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.pub_display.set_text("(clé publique s'affichera ici)")

    def _sign_section(self):
        card = SectionCard(self, title="  Signer un Message",
                           accent=T.get("PURPLE"), cia_keys=["A", "I"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(c, text="Message à signer :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=0, column=0, pady=(4, 0), sticky="w")
        self.sign_input = ctk.CTkTextbox(c, height=80, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("BORDER"), border_width=1)
        self.sign_input.grid(row=1, column=0, pady=4, sticky="ew")

        _btn(c, "Signer avec clé privée", self._sign,
             T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"), 200, 34
             ).grid(row=2, column=0, pady=6, sticky="w")

        ctk.CTkLabel(c, text="Signature (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=3, column=0, pady=(4, 0), sticky="w")
        self.sign_output = TerminalBox(c, height=80)
        sign_frame = ctk.CTkFrame(c, fg_color="transparent")
        sign_frame.grid(row=4, column=0, pady=4, sticky="ew")
        sign_frame.grid_columnconfigure(0, weight=1)
        self.sign_output = TerminalBox(sign_frame, height=80)
        self.sign_output.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(sign_frame, text="Copier", command=lambda: self.sign_output.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.sign_status = StatusBar(c)
        self.sign_status.grid(row=5, column=0, pady=2, sticky="w")

    def _verify_section(self):
        card = SectionCard(self, title="  Vérifier une Signature",
                           accent=T.get("GREEN"), cia_keys=["A", "I"])
        card.grid(row=3, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(c, text="Message à vérifier :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=0, column=0, pady=(4, 0), sticky="w")
        self.verify_msg = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("BORDER"), border_width=1)
        self.verify_msg.grid(row=1, column=0, pady=4, sticky="ew")

        sf = ctk.CTkFrame(c, fg_color="transparent")
        sf.grid(row=2, column=0, pady=4, sticky="ew")
        sf.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(sf, text="Signature (hex) :",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("PURPLE")).grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.verify_sig = ctk.CTkEntry(sf, font=ctk.CTkFont(family="Courier", size=12),
                                        fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"),
                                        text_color=T.get("TEXT_CODE"), placeholder_text="hex signature")
        self.verify_sig.grid(row=0, column=1, padx=4, sticky="ew")
        _btn(sf, "Charger", self._load_sig, T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"),
             80, 26).grid(row=0, column=2, padx=4)

        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=3, column=0, pady=4, sticky="w")
        _btn(bf, "Vérifier", self._verify, T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 130, 32).pack(side="left", padx=3)
        _btn(bf, "Tester altération", self._tamper_test, T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER"), 160, 32).pack(side="left", padx=3)

        self.verify_result = TerminalBox(c, height=70)
        verify_frame = ctk.CTkFrame(c, fg_color="transparent")
        verify_frame.grid(row=4, column=0, pady=4, sticky="ew")
        verify_frame.grid_columnconfigure(0, weight=1)
        self.verify_result = TerminalBox(verify_frame, height=70)
        self.verify_result.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(verify_frame, text="Copier", command=lambda: self.verify_result.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.verify_status = StatusBar(c)
        self.verify_status.grid(row=5, column=0, pady=2, sticky="w")

    def _attack_section(self):
        card = SectionCard(self, title="  SIMULATION SIGNATURE — Attaquant",
                           accent=T.get("RED"), cia_keys=["A"])
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            c,
            text=("Jouez l'attaquant : tenter de falsifier ou corrompre un message signé en 3 étapes."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        ctk.CTkLabel(c, text="Message utilisateur :", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM")).grid(row=1, column=0, sticky="w")
        self.sim_sig_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"), border_width=1)
        self.sim_sig_input.grid(row=2, column=0, pady=4, sticky="ew")

        step_frame = ctk.CTkFrame(c, fg_color="transparent")
        step_frame.grid(row=3, column=0, pady=4, sticky="w")
        _btn(step_frame, "Étape 1 : Signer", self._sim_sig_step1,
             T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"), 140, 30).pack(side="left", padx=3)

        attack_frame = ctk.CTkFrame(c, fg_color="transparent")
        attack_frame.grid(row=4, column=0, pady=4, sticky="w")
        ctk.CTkLabel(attack_frame, text="Attaque :", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM")).pack(side="left", padx=(0,4))
        self.sim_sig_method = ctk.CTkOptionMenu(attack_frame, values=[
            "Modifier message",
            "Corrompre signature",
            "Mauvaise clé privée",
            "Replay message modifié",
            "Pas de vérification"
        ],
        width=220, fg_color=T.get("BG_HOVER"), button_color=T.get("RED_BORDER"), button_hover_color=T.get("RED_HOVER"),
        text_color=T.get("TEXT_DIM"), font=ctk.CTkFont(size=12))
        self.sim_sig_method.set("Modifier message")
        self.sim_sig_method.pack(side="left", padx=3)

        _btn(attack_frame, "Étape 2 : Attaque", self._sim_sig_step2,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 140, 30).pack(side="left", padx=3)
        _btn(attack_frame, "Nouvelle simulation", self._sim_sig_reset,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), 150, 30).pack(side="left", padx=3)

        verify_frame = ctk.CTkFrame(c, fg_color="transparent")
        verify_frame.grid(row=5, column=0, pady=4, sticky="w")
        _btn(verify_frame, "Étape 3 : Vérifier", self._sim_sig_step3,
             T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 130, 30).pack(side="left", padx=3)

        self.sim_sig_status = ctk.CTkLabel(c, text="Statut : prêt.", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM"))
        self.sim_sig_status.grid(row=6, column=0, pady=(2,4), sticky="w")

        self.attack_log = TerminalBox(c, height=160)
        self.attack_log.grid(row=7, column=0, pady=4, sticky="ew")

        self.attack_status = StatusBar(c)
        self.attack_status.grid(row=8, column=0, pady=2, sticky="w")

        self._sim_sig_reset()

    def _set_sig_status(self, text, level="info"):
        color = T.get("TEXT_DIM")
        if level == "ok":
            color = T.get("GREEN")
        elif level == "error":
            color = T.get("RED")
        elif level == "warning":
            color = T.get("AMBER")
        self.sim_sig_status.configure(text=f"Statut : {text}", text_color=color)

    def _sim_sig_reset(self):
        self._sim_sig_step = 0
        self._sim_sig_message = ""
        self._sim_sig_original = ""
        self._sim_sig_signature = None
        self._sim_sig_attacked_message = ""
        self._sim_sig_attacked_signature = None
        self._sim_sig_used_key = "good"
        self.sim_sig_input.delete("0.0", "end")
        self.attack_log.clear()
        self._set_sig_status("Prêt pour nouvelle simulation.", "info")
        self.attack_status.clear()

    def _sim_sig_step1(self):
        msg = self.sim_sig_input.get("0.0", "end").strip()
        if not msg:
            self._set_sig_status("Message vide.", "error")
            return
        if not self._priv:
            self._set_sig_status("Générez ou importez une clé privée avant.", "error")
            return

        self._sim_sig_message = msg
        self._sim_sig_original = msg
        self._sim_sig_signature = self.ds.sign_text(msg, self._priv)
        sig_hex = self.ds.signature_to_hex(self._sim_sig_signature)
        self._sim_sig_step = 1
        self.attack_log.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  ÉTAPE 1 — L'émetteur signe avec sa clé PRIVÉE.         ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"Message         : {msg!r}\n"
            f"Longueur        : {len(msg)} caractères\n\n"
            f"Processus RSA-PSS :\n"
            f"  1. SHA-256({msg!r}) → condensé 32 octets\n"
            f"  2. PSS padding + salt aléatoire\n"
            f"  3. RSA decrypt(clé_privée, condensé_paddé) → signature\n\n"
            f"Signature (256 oct / {len(sig_hex)} chars hex) :\n"
            f"  {sig_hex[:64]}\n"
            f"  {sig_hex[64:128]}...\n\n"
            "→ La signature est envoyée avec le message.\n"
            "→ N'importe qui avec la clé PUBLIQUE peut vérifier."
        )
        self._set_sig_status("Message signé avec RSA-PSS/SHA-256.", "ok")
        self.attack_status.set("Étape 1 terminée — signature produite.", "ok")

    def _sim_sig_step2(self):
        if self._sim_sig_step < 1:
            self._set_sig_status("Exécutez l'étape 1 d'abord.", "warning")
            return
        mode = self.sim_sig_method.get()

        if mode == "Modifier message":
            orig_last = self._sim_sig_original[-1] if self._sim_sig_original else "X"
            new_last = "X" if not self._sim_sig_original.endswith("X") else "Y"
            self._sim_sig_attacked_message = self._sim_sig_original[:-1] + new_last
            self._sim_sig_attacked_signature = self._sim_sig_signature
            self._sim_sig_used_key = "good"
            explanation = (
                "TECHNIQUE : L'attaquant intercepte le message, modifie un caractère\n"
                "mais renvoie la signature ORIGINALE (qu'il ne peut pas régénérer).\n\n"
                f"Original  : {self._sim_sig_original!r}\n"
                f"Falsifié  : {self._sim_sig_attacked_message!r}\n"
                f"Signature : inchangée (l'attaquant ne connaît pas la clé privée)\n\n"
                "RÉSULTAT ATTENDU → vérification ÉCHOUE.\n"
                "RSA-PSS vérifie SHA256(message) == décryptage(sig, pub_key)\n"
                "→ SHA256(msg_modifié) ≠ SHA256(msg_original) → INVALIDE."
            )

        elif mode == "Corrompre signature":
            sigb = bytearray(self._sim_sig_signature)
            original_byte = sigb[0]
            sigb[0] ^= 0xFF
            self._sim_sig_attacked_signature = bytes(sigb)
            self._sim_sig_attacked_message = self._sim_sig_original
            self._sim_sig_used_key = "good"
            explanation = (
                "TECHNIQUE : L'attaquant modifie 1 octet de la signature.\n"
                "La signature RSA est un nombre de 256 octets (2048 bits).\n\n"
                f"Octet[0] original : 0x{original_byte:02X}\n"
                f"Octet[0] modifié  : 0x{original_byte ^ 0xFF:02X}\n\n"
                "RSA-PSS vérifie en recalculant RSA_encrypt(sig, pub_key)\n"
                "→ Le résultat ne correspond plus au hash paddé → INVALIDE.\n\n"
                "RÉSULTAT ATTENDU → vérification ÉCHOUE systématiquement.\n"
                "La signature RSA ne tolère aucune modification."
            )

        elif mode == "Mauvaise clé privée":
            if not self._priv:
                self._set_sig_status("Clé privée manquante.", "error")
                return
            bad_priv, _ = self.asym.generate_key_pair(2048)
            self._sim_sig_attacked_signature = self.ds.sign_text(self._sim_sig_original, bad_priv)
            self._sim_sig_attacked_message = self._sim_sig_original
            self._sim_sig_used_key = "bad"
            explanation = (
                "TECHNIQUE : L'attaquant n'a pas la clé privée du vrai signataire.\n"
                "Il génère SA PROPRE paire RSA et signe avec sa clé privée.\n\n"
                "Message      : identique à l'original\n"
                "Signature    : générée par une AUTRE clé privée (inconnue du destinataire)\n\n"
                "Vérification : destinataire utilise la clé PUBLIQUE du vrai signataire\n"
                "→ RSA_encrypt(mauvaise_sig, vraie_pub) ≠ hash_paddé → INVALIDE.\n\n"
                "RÉSULTAT ATTENDU → échec de vérification.\n"
                "Cas réel : usurpation d'identité — l'attaquant se fait passer pour l'émetteur."
            )

        elif mode == "Replay message modifié":
            self._sim_sig_attacked_message = self._sim_sig_original + " [REPLAY MODIFIÉ]"
            self._sim_sig_attacked_signature = self._sim_sig_signature
            self._sim_sig_used_key = "good"
            explanation = (
                "TECHNIQUE : Replay attack — réutiliser une signature valide sur un message différent.\n\n"
                f"Message rejoué  : {self._sim_sig_attacked_message!r}\n"
                f"Signature       : celle du message ORIGINAL\n\n"
                "Différence avec le replay pur :\n"
                "→ Ici le message EST modifié. La signature ne correspond plus.\n"
                "→ Même si l'attaquant rejouait le message EXACT + signature,\n"
                "  un bon protocole inclut un nonce/timestamp dans le message signé.\n\n"
                "RÉSULTAT ATTENDU → vérification ÉCHOUE (message modifié)."
            )

        elif mode == "Pas de vérification":
            self._sim_sig_attacked_message = self._sim_sig_original + " [FALSIFIÉ sans contrôle]"
            self._sim_sig_attacked_signature = self._sim_sig_signature
            self._sim_sig_used_key = "good"
            explanation = (
                "SCÉNARIO CRITIQUE : Le système récepteur n'implémente PAS la vérification.\n\n"
                "C'est l'erreur la plus courante en production :\n"
                "  • API qui accepte n'importe quel message sans valider la signature\n"
                "  • Signature présente mais vérification commentée / désactivée\n"
                "  • JWT avec algorithme 'none' accepté\n\n"
                "IMPACT : L'attaquant peut envoyer N'IMPORTE QUEL contenu\n"
                "comme s'il venait du vrai signataire.\n\n"
                "MITIGATION : Toujours vérifier avant de traiter. Ne jamais trust sans verify."
            )
        else:
            self._set_sig_status("Attaque inconnue.", "error")
            return

        sig_hex = self.ds.signature_to_hex(self._sim_sig_attacked_signature)
        self._sim_sig_step = 2
        self.attack_log.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            f"║  ÉTAPE 2 — Attaque : {mode:<35}║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"{explanation}\n\n"
            f"─────────────────────────────────────────────────────\n"
            f"Message transmis : {self._sim_sig_attacked_message!r}\n"
            f"Signature        : {sig_hex[:64]}..."
        )
        self._set_sig_status("Attaque construite — passez à l'étape 3.", "ok")
        self.attack_status.set("Attaque prête.", "info")

    def _sim_sig_step3(self):
        if self._sim_sig_step < 2:
            self._set_sig_status("Exécutez d'abord les étapes 1 et 2.", "warning")
            return

        mode = self.sim_sig_method.get()

        if mode == "Pas de vérification":
            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                "║  ÉTAPE 3 — VERDICT : Pas de vérification                ║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                "⚠️  FAILLE CRITIQUE — Aucune vérification effectuée.\n\n"
                f"Message reçu       : {self._sim_sig_attacked_message!r}\n"
                "Signature vérifiée : NON\n"
                "Résultat           : Message accepté sans contrôle\n\n"
                "L'attaquant a réussi à faire accepter un faux message.\n\n"
                "EXPLOITS RÉELS de ce pattern :\n"
                "  • CVE-2022-21449 (Psychic Signatures) — Java ECDSA bypass\n"
                "  • JWT 'alg:none' attack — signature ignorée\n"
                "  • OAuth tokens acceptés sans vérification de signature\n\n"
                "RÈGLE D'OR : Never trust, always verify."
            )
            self._set_sig_status("Attaque réussie — aucun contrôle.", "warning")
            self.attack_status.set("⚠️  Message falsifié accepté sans vérification.", "warning")
            return

        try:
            valid = self.ds.verify_text(self._sim_sig_attacked_message, self._sim_sig_attacked_signature, self._pub)
        except Exception as e:
            valid = False
            verify_error = str(e)
        else:
            verify_error = None

        sig_hex_orig = self.ds.signature_to_hex(self._sim_sig_signature)
        sig_hex_attack = self.ds.signature_to_hex(self._sim_sig_attacked_signature)
        sig_changed = sig_hex_orig != sig_hex_attack

        if valid:
            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                "║  ÉTAPE 3 — VERDICT : Signature VALIDE (inattendu)       ║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                "✅  La signature est valide — ceci indique que le message n'a pas été\n"
                "    modifié de façon significative (ou une faille grave existe).\n\n"
                f"Message vérifié : {self._sim_sig_attacked_message!r}\n"
                f"Clé utilisée    : {'vraie clé publique' if self._sim_sig_used_key == 'good' else 'mauvaise clé'}\n"
            )
            self._set_sig_status("Signature valide.", "ok")
            self.attack_status.set("✅ Signature valide.", "ok")
        else:
            # Construire l'analyse selon le mode
            if mode == "Modifier message":
                import hashlib
                h1 = hashlib.sha256(self._sim_sig_original.encode()).hexdigest()
                h2 = hashlib.sha256(self._sim_sig_attacked_message.encode()).hexdigest()
                analysis = (
                    "RSA-PSS a détecté la falsification :\n"
                    f"  SHA256(msg_original)   → {h1[:32]}...\n"
                    f"  SHA256(msg_falsifié)   → {h2[:32]}...\n"
                    "  Ces deux condensés sont différents → signature invalide.\n\n"
                    "CONCLUSION : Impossible de modifier un message signé sans invalider la signature."
                )
            elif mode == "Corrompre signature":
                analysis = (
                    "La signature corrompue ne correspond plus au condensé du message.\n"
                    f"  Signature originale  : {sig_hex_orig[:32]}...\n"
                    f"  Signature corrompue  : {sig_hex_attack[:32]}...\n\n"
                    "RSA-PSS : la vérification décode la signature avec la clé publique\n"
                    "et compare au hash paddé — la moindre altération = INVALIDE."
                )
            elif mode == "Mauvaise clé privée":
                analysis = (
                    "La signature générée par une AUTRE clé privée ne peut pas être\n"
                    "vérifiée avec la clé publique du vrai signataire.\n\n"
                    "Mathématiquement : RSA_encrypt(RSA_decrypt(msg, bad_priv), good_pub) ≠ msg\n"
                    "car (bad_priv, good_pub) ne forment pas une paire valide.\n\n"
                    "→ L'usurpation d'identité est impossible sans la vraie clé privée."
                )
            elif mode == "Replay message modifié":
                analysis = (
                    "Le replay d'une signature sur un message modifié échoue.\n"
                    f"  Message signé   : {self._sim_sig_original!r}\n"
                    f"  Message rejoué  : {self._sim_sig_attacked_message!r}\n\n"
                    "SHA256 des deux messages est différent → signature invalide.\n\n"
                    "POUR UN VRAI REPLAY (même message exact) :\n"
                    "→ La signature serait valide ! La protection anti-replay nécessite\n"
                    "  un timestamp ou nonce inclus dans le message signé."
                )
            else:
                analysis = f"Erreur de vérification : {verify_error}"

            self.attack_log.set_text(
                "╔══════════════════════════════════════════════════════════╗\n"
                f"║  ÉTAPE 3 — VERDICT : {mode:<35}║\n"
                "╚══════════════════════════════════════════════════════════╝\n\n"
                "❌  SIGNATURE INVALIDE — Attaque bloquée par RSA-PSS.\n\n"
                f"{analysis}"
            )
            self._set_sig_status("Signature invalide — falsification détectée.", "ok")
            self.attack_status.set("❌ Signature invalide — RSA-PSS a tenu.", "ok")

    # ── Handlers ──────────────────────────────────────────────────────

    def _gen(self):
        self.key_status.set("Génération RSA-2048...", "loading"); self.update()
        self._priv, self._pub = self.asym.generate_key_pair(2048)
        os.makedirs("keys", exist_ok=True)
        open("keys/sig_private.pem", "wb").write(self.asym.private_key_to_pem(self._priv))
        pub_pem = self.asym.public_key_to_pem(self._pub)
        open("keys/sig_public.pem", "wb").write(pub_pem)
        self.pub_display.set_text(pub_pem.decode())
        self.key_status.set("Paire RSA-2048 générée → keys/sig_*.pem", "ok")

    def _import_priv(self):
        path = filedialog.askopenfilename(title="Clé privée RSA (.pem)")
        if not path: return
        try:
            pem = open(path, "rb").read()
            self._priv = self.asym.private_key_from_pem(pem)
            self._pub  = self._priv.public_key()
            self.pub_display.set_text(self.asym.public_key_to_pem(self._pub).decode())
            self.key_status.set(f"Clé privée importée.", "ok")
        except Exception as e:
            self.key_status.set(str(e), "error")

    def _import_pub(self):
        path = filedialog.askopenfilename(title="Clé publique RSA (.pem)")
        if not path: return
        try:
            pem = open(path, "rb").read()
            self._pub = self.asym.public_key_from_pem(pem)
            self.pub_display.set_text(pem.decode())
            self.key_status.set(f"Clé publique importée.", "ok")
        except Exception as e:
            self.key_status.set(str(e), "error")

    def _export(self):
        if not self._priv:
            self.key_status.set("Aucune clé à exporter.", "warning"); return
        os.makedirs("keys", exist_ok=True)
        open("keys/sig_private.pem", "wb").write(self.asym.private_key_to_pem(self._priv))
        open("keys/sig_public.pem",  "wb").write(self.asym.public_key_to_pem(self._pub))
        self.key_status.set("Clés exportées → keys/sig_*.pem", "ok")

    def _sign(self):
        try:
            if not self._priv: raise ValueError("Générez ou importez une clé privée.")
            text = self.sign_input.get("0.0", "end").strip()
            if not text: raise ValueError("Message vide.")
            self._sig = self.ds.sign_text(text, self._priv)
            self.sign_output.set_text(self.ds.signature_to_hex(self._sig))
            self.sign_status.set(f"Signé ({len(self._sig)} octets) avec RSA-PSS / SHA-256.", "ok")
        except Exception as e:
            self.sign_status.set(str(e), "error")

    def _load_sig(self):
        if not self._sig: return
        self.verify_sig.delete(0, "end")
        self.verify_sig.insert(0, self.ds.signature_to_hex(self._sig))
        msg = self.sign_input.get("0.0", "end").strip()
        self.verify_msg.delete("0.0", "end")
        self.verify_msg.insert("0.0", msg)

    def _verify(self):
        try:
            if not self._pub: raise ValueError("Aucune clé publique.")
            msg = self.verify_msg.get("0.0", "end").strip()
            h   = self.verify_sig.get().strip()
            if not msg or not h: raise ValueError("Message et signature requis.")
            valid = self.ds.verify_text(msg, self.ds.signature_from_hex(h), self._pub)
            icon  = "✅" if valid else "❌"
            self.verify_result.set_text(
                f"Message  : {msg[:70]}\n"
                f"Résultat : {icon} {'SIGNATURE VALIDE' if valid else 'SIGNATURE INVALIDE'}")
            self.verify_status.set(
                "Signature valide — authenticité confirmée." if valid
                else "SIGNATURE INVALIDE — message altéré ou mauvaise clé!",
                "ok" if valid else "attack")
        except Exception as e:
            self.verify_status.set(str(e), "error")

    def _tamper_test(self):
        try:
            if not self._sig or not self._pub:
                raise ValueError("Signez d'abord un message.")
            tampered = self.sign_input.get("0.0", "end").strip() + " [FALSIFIÉ]"
            self.verify_msg.delete("0.0", "end")
            self.verify_msg.insert("0.0", tampered)
            self.verify_sig.delete(0, "end")
            self.verify_sig.insert(0, self.ds.signature_to_hex(self._sig))
            valid = self.ds.verify_text(tampered, self._sig, self._pub)
            self.verify_result.set_text(
                f"Message falsifié : {tampered[:70]}\n"
                f"Résultat         : {'✅ Valide' if valid else '❌ INVALIDE — falsification détectée!'}")
            self.verify_status.set("Falsification correctement détectée!", "attack")
        except Exception as e:
            self.verify_status.set(str(e), "error")

    # (Ancienne simulation non interactive remplacée par le nouveau flux étape par étape.)
