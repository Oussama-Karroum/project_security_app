"""
integrity_page.py — SHA-256 live hash, avalanche demo, attack simulation.
All colors are valid 6-char hex strings.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import time, threading

from core.hashing import HashManager
import gui.theme as T

from gui.widgets import CIABadge, ToolTipButton, TerminalBox, SectionCard, StatusBar


def _btn(parent, text, cmd, fg, tc, bc, hc, width=140, height=30):
    return ctk.CTkButton(parent, text=text, command=cmd, width=width, height=height,
                          fg_color=fg, hover_color=hc, text_color=tc,
                          border_width=1, border_color=bc)


class IntegrityPage(ctk.CTkScrollableFrame):

    INFO = (
        "Objectif CIA : INTÉGRITÉ — garantir que les données n'ont pas été altérées.\n"
        "SHA-256 produit un condensé déterministe de 256 bits. "
        "L'effet avalanche garantit qu'un seul bit modifié change ~50% du condensé.\n"
        "Limite : le hash seul ne prouve pas l'origine — combinez avec une signature pour l'authenticité."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color=T.get("BG_DEEP"), scrollbar_button_color=T.get("BORDER"))
        self.grid_columnconfigure(0, weight=1)
        self.hm  = HashManager()
        self._ref_hash   = None
        self._after_id   = None
        self._prev_hash  = None
        self._build()

    def _build(self):
        self._header()
        self._live_section()
        self._verify_section()
        self._avalanche_section()
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
        ctk.CTkLabel(top, text="🔗  INTÉGRITÉ",
                     font=ctk.CTkFont(family="Courier", size=15, weight="bold"),
                     text_color=T.get("TEAL")).grid(row=0, column=0, sticky="w")
        CIABadge(top, ["I"]).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(f, text=self.INFO, font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"), wraplength=820, justify="left",
                     ).grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")

    # ── Live section ──────────────────────────────────────────────────

    def _live_section(self):
        card = SectionCard(self, title="  SHA-256  —  Visualisation en Temps Réel",
                           accent=T.get("TEAL"), cia_keys=["I"])
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        tip_row = ctk.CTkFrame(c, fg_color="transparent")
        tip_row.grid(row=0, column=0, pady=4, sticky="w")
        ToolTipButton(tip_row, "SHA-256").pack(side="left", padx=2)
        ctk.CTkLabel(tip_row, text="Le condensé se met à jour à chaque frappe",
                     font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM")).pack(side="left", padx=8)

        ctk.CTkLabel(c, text="Texte :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=1, column=0, pady=(4, 0), sticky="w")
        self.live_input = ctk.CTkTextbox(c, height=75, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("TEAL_BORDER"), border_width=1)
        self.live_input.grid(row=2, column=0, pady=4, sticky="ew")
        self.live_input.bind("<KeyRelease>", self._on_key)

        # Hash display bar
        hash_bar = ctk.CTkFrame(c, fg_color=T.get("BG_DEEP"), corner_radius=6,
                                  border_width=1, border_color=T.get("TEAL_BORDER"))
        hash_bar.grid(row=3, column=0, pady=4, sticky="ew")
        hash_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hash_bar, text="SHA-256 :",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("TEAL")).grid(row=0, column=0, padx=10, pady=8, sticky="w")
        self.live_hash_lbl = ctk.CTkLabel(
            hash_bar, text="(tapez pour voir le condensé live)",
            font=ctk.CTkFont(family="Courier", size=13), text_color=T.get("TEXT_CODE"))
        self.live_hash_lbl.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        self.live_len_lbl = ctk.CTkLabel(
            hash_bar, text="", font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM"))
        self.live_len_lbl.grid(row=0, column=2, padx=10, pady=8, sticky="e")

        # Diff bar — 64 cells showing changed hex chars
        self.diff_canvas = tk.Canvas(c, height=18, bg=T.get("BG_DEEP"), highlightthickness=0)
        self.diff_canvas.grid(row=4, column=0, pady=(0, 4), sticky="ew")

        # Buttons
        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=5, column=0, pady=4, sticky="w")
        _btn(bf, "# Hash texte",    self._hash_text,   T.get("TEAL_BG"), T.get("TEAL"), T.get("TEAL_BORDER"), T.get("TEAL_HOVER"), 130).pack(side="left", padx=3)
        _btn(bf, "📂 Hash fichier", self._hash_file,   T.get("TEAL_BG"), T.get("TEAL"), T.get("TEAL_BORDER"), T.get("TEAL_HOVER"), 130).pack(side="left", padx=3)
        _btn(bf, "📌 Mémoriser",    self._save_ref,    T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"),  T.get("CYAN_HOVER"), 110).pack(side="left", padx=3)

        self.live_status = StatusBar(c)
        self.live_status.grid(row=6, column=0, pady=2, sticky="w")

    # ── Verify section ────────────────────────────────────────────────

    def _verify_section(self):
        card = SectionCard(self, title="  Vérification d'Intégrité",
                           accent=T.get("GREEN"), cia_keys=["I"])
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(c, text="Texte à vérifier :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=0, column=0, pady=(4, 0), sticky="w")
        self.verify_input = ctk.CTkTextbox(c, height=70, fg_color=T.get("BG_DEEP"),
                                            border_color=T.get("BORDER"), border_width=1)
        self.verify_input.grid(row=1, column=0, pady=4, sticky="ew")

        rf = ctk.CTkFrame(c, fg_color="transparent")
        rf.grid(row=2, column=0, pady=4, sticky="ew")
        rf.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(rf, text="Hash référence :",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("GREEN")).grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.verify_ref = ctk.CTkEntry(rf, font=ctk.CTkFont(family="Courier", size=13),
                                        fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"),
                                        text_color=T.get("TEXT_CODE"),
                                        placeholder_text="hash SHA-256 attendu (64 chars hex)")
        self.verify_ref.grid(row=0, column=1, padx=4, sticky="ew")
        _btn(rf, "Utiliser mémorisé", self._use_ref, T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"),
             130, 26).grid(row=0, column=2, padx=4)

        _btn(c, "✅ Vérifier intégrité", self._verify,
             T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 180, 32
             ).grid(row=3, column=0, pady=6, sticky="w")

        self.verify_result = TerminalBox(c, height=80)
        self.verify_result.grid(row=4, column=0, pady=4, sticky="ew")
        self.verify_status = StatusBar(c)
        self.verify_status.grid(row=5, column=0, pady=2, sticky="w")

    # ── Avalanche section ─────────────────────────────────────────────

    def _avalanche_section(self):
        card = SectionCard(self, title="  💥  Effet Avalanche — Démonstration",
                           accent=T.get("AMBER"), cia_keys=["I"])
        card.grid(row=3, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        c.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(c, text="Message original :", font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM")).grid(row=0, column=0, pady=(4, 0), sticky="w")
        self.aval_input = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("BORDER"), border_width=1)
        self.aval_input.grid(row=1, column=0, padx=(0, 4), pady=4, sticky="ew")
        self.aval_input.insert("0.0", "Bonjour, ceci est un message de test.")

        ctk.CTkLabel(c, text="Message altéré (auto) :", font=ctk.CTkFont(size=13),
                     text_color=T.get("RED")).grid(row=0, column=1, pady=(4, 0), sticky="w")
        self.aval_modified = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                             border_color=T.get("RED_BORDER"), border_width=1)
        self.aval_modified.grid(row=1, column=1, padx=(4, 0), pady=4, sticky="ew")

        _btn(c, "💥 Simuler altération", self._simulate_avalanche,
             T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER"), 180, 32
             ).grid(row=2, column=0, columnspan=2, pady=6, sticky="w")

        # Avalanche bar
        self.aval_canvas = tk.Canvas(c, height=26, bg=T.get("BG_DEEP"), highlightthickness=0)
        self.aval_canvas.grid(row=3, column=0, columnspan=2, pady=4, sticky="ew")

        self.aval_result = TerminalBox(c, height=90)
        self.aval_result.grid(row=4, column=0, columnspan=2, pady=4, sticky="ew")

    # ── Attack section ────────────────────────────────────────────────

    def _attack_section(self):
        card = SectionCard(self, title="  🔴  SIMULATION D'ATTAQUE — Falsification de Hash",
                           accent=T.get("RED"), cia_keys=["I"])
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            c,
            text=("Scénario : un attaquant modifie un contrat (1 caractère).\n"
                  "Résultat attendu : le hash SHA-256 change → la falsification est immédiatement détectée."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        _btn(c, "🔴 Lancer simulation", self._run_attack,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 180, 32
             ).grid(row=1, column=0, pady=4, sticky="w")

        self.attack_log = TerminalBox(c, height=130)
        self.attack_log.grid(row=2, column=0, pady=4, sticky="ew")
        self.attack_status = StatusBar(c)
        self.attack_status.grid(row=3, column=0, pady=2, sticky="w")

    # ── Live hash ─────────────────────────────────────────────────────

    def _on_key(self, event=None):
        if self._after_id:
            self.after_cancel(self._after_id)
        self._after_id = self.after(80, self._update_live)

    def _update_live(self):
        text = self.live_input.get("0.0", "end").rstrip("\n")
        if not text:
            self.live_hash_lbl.configure(text="(tapez pour voir le condensé live)")
            self.live_len_lbl.configure(text="")
            self.diff_canvas.delete("all")
            self._prev_hash = None
            return
        new_h = self.hm.hash_text(text)
        self.live_hash_lbl.configure(text=new_h)
        self.live_len_lbl.configure(text=f"{len(text)} car. → 256 bits")
        self._draw_diff(self._prev_hash, new_h)
        self._prev_hash = new_h

    def _draw_diff(self, old_h, new_h):
        cv = self.diff_canvas
        cv.delete("all")
        self.update_idletasks()
        W  = cv.winfo_width() or 700
        cw = W / 64
        for i, ch in enumerate(new_h):
            changed = old_h is None or (i < len(old_h or "") and old_h[i] != ch)
            color = T.get("AMBER") if changed else T.get("TEAL_BG")
            x0 = i * cw
            cv.create_rectangle(x0, 2, x0 + cw - 1, 16, fill=color, outline="")
            if cw > 9:
                cv.create_text(x0 + cw / 2, 9, text=ch,
                                font=("Courier", 7), fill=T.get("TEXT_CODE"))

    # ── Hash handlers ─────────────────────────────────────────────────

    def _hash_text(self):
        try:
            text = self.live_input.get("0.0", "end").strip()
            if not text: raise ValueError("Texte vide.")
            d = self.hm.hash_text(text)
            self.live_hash_lbl.configure(text=d)
            self.live_status.set("SHA-256 calculé — 256 bits / 64 chars hex", "ok")
        except Exception as e:
            self.live_status.set(str(e), "error")

    def _hash_file(self):
        try:
            path = filedialog.askopenfilename()
            if not path: return
            d = self.hm.hash_file(path)
            self.live_hash_lbl.configure(text=d)
            self.live_status.set(f"Hash fichier : {path.split('/')[-1]}", "ok")
        except Exception as e:
            self.live_status.set(str(e), "error")

    def _save_ref(self):
        h = self.live_hash_lbl.cget("text")
        if len(h) == 64:
            self._ref_hash = h
            self.live_status.set("Hash mémorisé comme référence.", "info")
        else:
            self.live_status.set("Calculez d'abord un hash.", "warning")

    def _use_ref(self):
        if self._ref_hash:
            self.verify_ref.delete(0, "end")
            self.verify_ref.insert(0, self._ref_hash)

    def _verify(self):
        try:
            text = self.verify_input.get("0.0", "end").strip()
            ref  = self.verify_ref.get().strip()
            if not text or not ref: raise ValueError("Texte et hash requis.")
            computed = self.hm.hash_text(text)
            match    = self.hm.verify_text_integrity(text, ref)
            icon     = "✅" if match else "❌"
            self.verify_result.set_text(
                f"Calculé   : {computed}\n"
                f"Référence : {ref}\n"
                f"Résultat  : {icon} {'INTÉGRITÉ CONFIRMÉE' if match else 'ALTÉRATION DÉTECTÉE'}"
            )
            self.verify_status.set(
                "Intégrité confirmée." if match else "ALTÉRATION DÉTECTÉE !",
                "ok" if match else "attack"
            )
        except Exception as e:
            self.verify_status.set(str(e), "error")

    # ── Avalanche ─────────────────────────────────────────────────────

    def _simulate_avalanche(self):
        original = self.aval_input.get("0.0", "end").strip()
        if not original: return
        modified = self.hm.simulate_tampering(original)
        self.aval_modified.delete("0.0", "end")
        self.aval_modified.insert("0.0", modified)
        cmp = self.hm.compare_hashes(original, modified)
        pct = cmp["diff_chars"] / 64 * 100
        self._draw_avalanche_bar(cmp["original_hash"], cmp["modified_hash"])
        self.aval_result.set_text(
            f"Original         : {original}\n"
            f"Altéré           : {modified}\n\n"
            f"Hash original    : {cmp['original_hash']}\n"
            f"Hash altéré      : {cmp['modified_hash']}\n\n"
            f"Chars différents : {cmp['diff_chars']} / 64  ({pct:.1f}% modifié)\n"
            f"Effet avalanche  : {'EXCELLENT' if pct > 40 else 'PARTIEL'} ✅"
        )

    def _draw_avalanche_bar(self, h1, h2):
        cv = self.aval_canvas
        cv.delete("all")
        self.update_idletasks()
        W  = cv.winfo_width() or 700
        cw = W / 64
        for i in range(64):
            changed = i < len(h1) and i < len(h2) and h1[i] != h2[i]
            color = T.get("RED_MED") if changed else T.get("GREEN_BG")
            cv.create_rectangle(i * cw, 3, i * cw + cw - 1, 23, fill=color, outline="")

    # ── Attack ────────────────────────────────────────────────────────

    def _run_attack(self):
        self.attack_log.clear()
        self.attack_status.set("Simulation en cours...", "loading"); self.update()
        threading.Thread(target=self._attack_thread, daemon=True).start()

    def _attack_thread(self):
        orig = "Contrat signé : virement de 10 000 MAD vers compte A."
        tamp = "Contrat signé : virement de 99 999 MAD vers compte B."
        h1   = self.hm.hash_text(orig)
        time.sleep(0.3)
        h2   = self.hm.hash_text(tamp)
        time.sleep(0.3)
        match = self.hm.verify_text_integrity(tamp, h1)

        lines = [
            "─" * 60, "  SIMULATION : Falsification de contrat", "─" * 60,
            f"\n[ÉMETTEUR] Message original :\n  {orig}",
            f"\n[ÉMETTEUR] Hash SHA-256 :\n  {h1}",
            f"\n[ATTAQUANT] Contenu falsifié :\n  {tamp}",
            f"\n[ATTAQUANT] Nouveau hash :\n  {h2}",
            "\n[DESTINATAIRE] Vérification...",
            f"[DESTINATAIRE] {'HASH VALIDE (inattendu)' if match else '❌ HASH INVALIDE — FALSIFICATION DÉTECTÉE !'}",
        ]
        if not match:
            lines += ["", "✅ SHA-256 PROTÈGE CONTRE LA FALSIFICATION",
                      "   Un seul caractère modifié → condensé totalement différent."]
        lines.append("\n" + "─" * 60)
        self.after(0, lambda: self.attack_log.set_text("\n".join(lines)))
        self.after(0, lambda: self.attack_status.set(
            "Falsification détectée par SHA-256.", "ok"))


# Import needed for avalanche bar T.get("RED_MED")
