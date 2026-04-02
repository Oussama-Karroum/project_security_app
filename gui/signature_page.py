"""
signature_page.py — RSA-PSS digital signature. All colors 6-char hex.
"""

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
        card = SectionCard(self, title="  🔑  Gestion des Clés RSA",
                           accent=T.get("PURPLE"), cia_keys=["A"])
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=0, column=0, pady=4, sticky="w")
        for txt, cmd in [("🔑 Générer RSA-2048", self._gen),
                          ("⬆ Importer clé privée", self._import_priv),
                          ("⬆ Importer clé publique", self._import_pub),
                          ("💾 Exporter clés", self._export)]:
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
        self.pub_display.grid(row=3, column=0, pady=4, sticky="ew")
        self.pub_display.set_text("(clé publique s'affichera ici)")

    def _sign_section(self):
        card = SectionCard(self, title="  ✍️   Signer un Message",
                           accent=T.get("PURPLE"), cia_keys=["A", "I"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(c, text="Message à signer :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=0, column=0, pady=(4, 0), sticky="w")
        self.sign_input = ctk.CTkTextbox(c, height=80, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("BORDER"), border_width=1)
        self.sign_input.grid(row=1, column=0, pady=4, sticky="ew")

        _btn(c, "✍️  Signer avec clé privée", self._sign,
             T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"), 200, 34
             ).grid(row=2, column=0, pady=6, sticky="w")

        ctk.CTkLabel(c, text="Signature (hex) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=3, column=0, pady=(4, 0), sticky="w")
        self.sign_output = TerminalBox(c, height=80)
        self.sign_output.grid(row=4, column=0, pady=4, sticky="ew")
        self.sign_status = StatusBar(c)
        self.sign_status.grid(row=5, column=0, pady=2, sticky="w")

    def _verify_section(self):
        card = SectionCard(self, title="  🔍  Vérifier une Signature",
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
        _btn(bf, "🔍 Vérifier", self._verify, T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 130, 32).pack(side="left", padx=3)
        _btn(bf, "💥 Tester altération", self._tamper_test, T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER"), 160, 32).pack(side="left", padx=3)

        self.verify_result = TerminalBox(c, height=70)
        self.verify_result.grid(row=4, column=0, pady=4, sticky="ew")
        self.verify_status = StatusBar(c)
        self.verify_status.grid(row=5, column=0, pady=2, sticky="w")

    def _attack_section(self):
        card = SectionCard(self, title="  🔴  SIMULATION — Falsification Post-Signature",
                           accent=T.get("RED"), cia_keys=["A"])
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            c,
            text=("Scénario : Alice signe un contrat. Eve modifie le montant APRÈS signature.\n"
                  "Résultat attendu : la vérification échoue → non-répudiation garantie."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        _btn(c, "🔴 Lancer simulation", self._run_attack,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 180, 32
             ).grid(row=1, column=0, pady=4, sticky="w")

        self.attack_log = TerminalBox(c, height=150)
        self.attack_log.grid(row=2, column=0, pady=4, sticky="ew")
        self.attack_status = StatusBar(c)
        self.attack_status.grid(row=3, column=0, pady=2, sticky="w")

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

    def _run_attack(self):
        if not self._priv or not self._pub:
            self.attack_status.set("Générez d'abord une paire RSA.", "warning"); return
        self.attack_log.clear()
        self.attack_status.set("Simulation en cours...", "loading"); self.update()
        threading.Thread(target=self._attack_thread, daemon=True).start()

    def _attack_thread(self):
        orig = "Je, soussigné Alice, autorise un virement de 5 000 MAD."
        tamp = "Je, soussigné Alice, autorise un virement de 50 000 MAD."
        sig  = self.ds.sign_text(orig, self._priv)
        time.sleep(0.3)
        valid = self.ds.verify_text(tamp, sig, self._pub)
        time.sleep(0.3)
        lines = [
            "─" * 62,
            "  SIMULATION : Falsification post-signature (Alice vs Eve)",
            "─" * 62,
            f"\n[ALICE]   Contrat original :\n  {orig}",
            f"\n[ALICE]   Signature RSA-PSS :\n  {sig.hex()[:48]}...",
            f"\n[EVE]     Contrat falsifié :\n  {tamp}",
            "\n[BANQUE]  Vérification de la signature...",
            f"[BANQUE]  {'✅ VALIDE (inattendu)' if valid else '❌ SIGNATURE INVALIDE — FALSIFICATION DÉTECTÉE !'}",
        ]
        if not valid:
            lines += [
                "",
                "GARANTIES DE LA SIGNATURE NUMÉRIQUE :",
                "  • Toute modification invalide la signature",
                "  • Eve ne peut pas forger sans la clé privée d'Alice",
                "  • Non-répudiation : Alice ne peut nier l'original",
            ]
        lines.append("\n" + "─" * 62)
        self.after(0, lambda: self.attack_log.set_text("\n".join(lines)))
        self.after(0, lambda: self.attack_status.set(
            "Falsification post-signature correctement détectée.", "ok"))
