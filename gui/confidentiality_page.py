"""
confidentiality_page.py — AES + RSA + Hybrid with attack simulation,
key import/export, hybrid step animation, CIA badges, tooltips.
All colors are valid 6-char hex strings.
"""

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
        ctk.CTkLabel(top, text="🔒  CONFIDENTIALITÉ",
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

        # Input / output
        ctk.CTkLabel(c, text="Texte :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=1, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                         border_color=T.get("BORDER"), border_width=1)
        self.aes_input.grid(row=1, column=1, columnspan=2, padx=4, pady=4, sticky="ew")

        abf = ctk.CTkFrame(c, fg_color="transparent")
        abf.grid(row=2, column=0, columnspan=3, pady=4, sticky="w")
        for txt, cmd in [("🔒 Chiffrer", self._aes_enc), ("🔓 Déchiffrer", self._aes_dec),
                          ("📂 Chiffrer fichier", self._aes_enc_file),
                          ("📂 Déchiffrer fichier", self._aes_dec_file)]:
            _btn(abf, txt, cmd, T.get("BLUE_BG"), T.get("BLUE"), T.get("BLUE_BORDER"), T.get("BLUE_HOVER"),
                 width=148, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Résultat :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=3, column=0, padx=(0, 6), pady=(6, 0), sticky="nw")
        self.aes_output = TerminalBox(c, height=55)
        self.aes_output.grid(row=3, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        self.aes_status = StatusBar(c)
        self.aes_status.grid(row=4, column=0, columnspan=3, pady=3, sticky="w")

    # ── RSA Section ───────────────────────────────────────────────────

    def _rsa_section(self):
        card = SectionCard(self, title="  RSA-2048  —  Chiffrement Asymétrique",
                           accent=T.get("PURPLE"), cia_keys=["C"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        kbf = ctk.CTkFrame(c, fg_color="transparent")
        kbf.grid(row=0, column=0, pady=4, sticky="ew")
        for txt, cmd in [("🔑 Générer RSA-2048", self._rsa_gen),
                          ("⬆ Importer clé privée", self._rsa_import_priv),
                          ("💾 Exporter clés", self._rsa_export)]:
            _btn(kbf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 width=170, height=30).pack(side="left", padx=3)
        ToolTipButton(kbf, "RSA").pack(side="left", padx=4)
        ToolTipButton(kbf, "OAEP").pack(side="left", padx=2)

        self.rsa_key_status = StatusBar(c)
        self.rsa_key_status.set("Aucune clé RSA chargée", "warning")
        self.rsa_key_status.grid(row=1, column=0, pady=2, sticky="w")

        ctk.CTkLabel(c, text="Texte (≤ 190 octets) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(6, 0), sticky="w")
        self.rsa_input = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                         border_color=T.get("BORDER"), border_width=1)
        self.rsa_input.grid(row=3, column=0, pady=4, sticky="ew")

        rbf = ctk.CTkFrame(c, fg_color="transparent")
        rbf.grid(row=4, column=0, pady=4, sticky="w")
        for txt, cmd in [("🔒 Chiffrer RSA", self._rsa_enc),
                          ("🔓 Déchiffrer RSA", self._rsa_dec)]:
            _btn(rbf, txt, cmd, T.get("PURPLE_BG"), T.get("PURPLE"), T.get("PURPLE_BORDER"), T.get("PURPLE_HOVER"),
                 width=160, height=30).pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Résultat :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=5, column=0, pady=(6, 0), sticky="w")
        self.rsa_output = TerminalBox(c, height=55)
        self.rsa_output.grid(row=6, column=0, pady=4, sticky="ew")
        self.rsa_status = StatusBar(c)
        self.rsa_status.grid(row=7, column=0, pady=2, sticky="w")

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

        ctk.CTkLabel(c, text="Message (taille illimitée) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(6, 0), sticky="w")
        self.hybrid_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                            border_color=T.get("BORDER"), border_width=1)
        self.hybrid_input.grid(row=3, column=0, pady=4, sticky="ew")

        hbf = ctk.CTkFrame(c, fg_color="transparent")
        hbf.grid(row=4, column=0, pady=4, sticky="w")
        _btn(hbf, "🔒 Chiffrement hybride", self._hybrid_enc_action,
             T.get("CYAN_BG"), T.get("CYAN"), T.get("CYAN_BORDER"), T.get("CYAN_HOVER"), width=180).pack(side="left", padx=3)
        _btn(hbf, "🔓 Déchiffrement hybride", self._hybrid_dec_action,
             T.get("CYAN_BG"), T.get("CYAN"), T.get("CYAN_BORDER"), T.get("CYAN_HOVER"), width=180).pack(side="left", padx=3)
        _btn(hbf, "▶ Animer", self._animate_hybrid,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), width=90).pack(side="left", padx=3)

        self.hybrid_output = TerminalBox(c, height=80)
        self.hybrid_output.grid(row=5, column=0, pady=4, sticky="ew")
        self.hybrid_status = StatusBar(c)
        self.hybrid_status.grid(row=6, column=0, pady=2, sticky="w")

    # ── Attack Section ────────────────────────────────────────────────

    def _attack_section(self):
        card = SectionCard(self, title="  🔴  SIMULATION D'ATTAQUE — Mauvaise Clé",
                           accent=T.get("RED"), cia_keys=["C"])
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            c,
            text=("Que se passe-t-il quand un attaquant utilise la mauvaise clé AES ?\n"
                  "Cette simulation chiffre un message avec la clé correcte, "
                  "puis tente de le déchiffrer avec une clé aléatoire différente."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"),
            wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        _btn(c, "🔴 Lancer simulation d'attaque", self._run_attack,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), width=220, height=34
             ).grid(row=1, column=0, pady=4, sticky="w")

        self.attack_log = TerminalBox(c, height=130)
        self.attack_log.grid(row=2, column=0, pady=4, sticky="ew")
        self.attack_status = StatusBar(c)
        self.attack_status.grid(row=3, column=0, pady=2, sticky="w")

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
            h   = self.aes_output.get("0.0", "end").strip()
            if not h: raise ValueError("Aucun ciphertext.")
            pt = self.sym.decrypt_text(bytes.fromhex(h), key)
            self.aes_input.delete("0.0", "end")
            self.aes_input.insert("0.0", pt)
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
            pt = self.asym.decrypt(bytes.fromhex(self.rsa_output.get("0.0", "end").strip()),
                                    self._rsa_priv)
            self.rsa_input.delete("0.0", "end")
            self.rsa_input.insert("0.0", pt.decode())
            self.rsa_status.set("Déchiffrement RSA réussi.", "ok")
        except Exception as e:
            self.rsa_status.set(str(e), "error")

    # ── Hybrid handlers ───────────────────────────────────────────────

    def _hybrid_enc_action(self):
        try:
            if not self._rsa_pub: raise ValueError("Générez une paire RSA d'abord.")
            text = self.hybrid_input.get("0.0", "end").strip()
            if not text: raise ValueError("Message vide.")
            self._hybrid_enc = self.asym.hybrid_encrypt(text, self._rsa_pub)
            out = (f"[Clé AES chiffrée RSA]\n"
                   f"{self._hybrid_enc['encrypted_aes_key'].hex()[:64]}...\n\n"
                   f"[Ciphertext AES]\n{self._hybrid_enc['ciphertext'].hex()[:64]}...")
            self.hybrid_output.set_text(out)
            self.hybrid_status.set("Chiffrement hybride réussi.", "ok")
            self._animate_hybrid()
        except Exception as e:
            self.hybrid_status.set(str(e), "error")

    def _hybrid_dec_action(self):
        try:
            if not self._rsa_priv: raise ValueError("Aucune clé privée RSA.")
            if not self._hybrid_enc: raise ValueError("Chiffrez d'abord un message.")
            pt = self.asym.hybrid_decrypt(
                self._hybrid_enc["encrypted_aes_key"],
                self._hybrid_enc["ciphertext"], self._rsa_priv)
            self.hybrid_output.set_text(f"[Message déchiffré]\n{pt}")
            self.hybrid_status.set("Déchiffrement hybride réussi.", "ok")
        except Exception as e:
            self.hybrid_status.set(str(e), "error")

    # ── Attack simulation ─────────────────────────────────────────────

    def _run_attack(self):
        self.attack_log.clear()
        self.attack_status.set("Simulation en cours...", "loading"); self.update()
        threading.Thread(target=self._attack_thread, daemon=True).start()

    def _attack_thread(self):
        msg = "Message confidentiel — ENSAF Cryptographie 2024"
        correct = self.sym.generate_key()
        wrong   = self.sym.generate_key()
        ct      = self.sym.encrypt_text(msg, correct)
        time.sleep(0.2)

        lines = [
            "─" * 56,
            "  SIMULATION : Attaque par mauvaise clé AES-256",
            "─" * 56,
            f"\n[1] Message         : {msg}",
            f"[2] Clé correcte    : {correct.hex()[:24]}...",
            f"[3] Mauvaise clé    : {wrong.hex()[:24]}...",
            f"[4] Ciphertext      : {ct.hex()[:32]}...",
            "\n[5] Tentative avec la MAUVAISE clé...",
        ]
        time.sleep(0.3)

        try:
            self.sym.decrypt_text(ct, wrong)
            lines.append("[6] Résultat inattendu : déchiffrement accepté")
        except Exception as e:
            lines += [
                f"[6] RÉSULTAT  : ÉCHEC — {e}",
                "",
                "SÉCURITÉ CONFIRMÉE",
                "  AES-CBC avec la mauvaise clé produit une erreur",
                "  de dépadding. L'attaquant NE PEUT PAS récupérer",
                "  le message sans la clé correcte.",
            ]

        time.sleep(0.3)
        pt = self.sym.decrypt_text(ct, correct)
        lines += [f"\n[7] Déchiffrement correct : {pt}", "\n" + "─" * 56]

        text = "\n".join(lines)
        self.after(0, lambda: self.attack_log.set_text(text))
        self.after(0, lambda: self.attack_status.set(
            "Simulation terminée — mauvaise clé correctement rejetée.", "ok"))
