import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import time
import threading
import hmac as _hmac_mod

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
        self.hm = HashManager()
        self._ref_hash  = None
        self._after_id  = None
        self._prev_hash = None
        self._build()

    def _build(self):
        self._header()
        self._live_section()
        self._verify_section()
        self._avalanche_section()
        self._attack_section()
        self._timing_section()
        self._mitm_section()

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

        self.diff_canvas = tk.Canvas(c, height=18, bg=T.get("BG_DEEP"), highlightthickness=0)
        self.diff_canvas.grid(row=4, column=0, pady=(0, 4), sticky="ew")

        bf = ctk.CTkFrame(c, fg_color="transparent")
        bf.grid(row=5, column=0, pady=4, sticky="w")
        _btn(bf, "Hash texte",   self._hash_text,  T.get("TEAL_BG"), T.get("TEAL"), T.get("TEAL_BORDER"), T.get("TEAL_HOVER"), 120).pack(side="left", padx=3)
        _btn(bf, "Hash fichier", self._hash_file,  T.get("TEAL_BG"), T.get("TEAL"), T.get("TEAL_BORDER"), T.get("TEAL_HOVER"), 120).pack(side="left", padx=3)
        _btn(bf, "Mémoriser",    self._save_ref,   T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), 110).pack(side="left", padx=3)
        _btn(bf, "Effacer",      self._hash_clear, T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"),  90).pack(side="left", padx=3)

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
        _btn(rf, "Utiliser mémorisé", self._use_ref, T.get("BG_HOVER"), T.get("TEXT_DIM"),
             T.get("BORDER"), T.get("CYAN_HOVER"), 130, 26).grid(row=0, column=2, padx=4)

        _btn(c, "Vérifier intégrité", self._verify,
             T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 180, 32
             ).grid(row=3, column=0, pady=6, sticky="w")

        verify_frame = ctk.CTkFrame(c, fg_color="transparent")
        verify_frame.grid(row=4, column=0, pady=4, sticky="ew")
        verify_frame.grid_columnconfigure(0, weight=1)
        self.verify_result = TerminalBox(verify_frame, height=80)
        self.verify_result.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        ctk.CTkButton(verify_frame, text="Copier", command=lambda: self.verify_result.copy_to_clipboard(),
                      width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                      text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER")
                      ).grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.verify_status = StatusBar(c)
        self.verify_status.grid(row=5, column=0, pady=2, sticky="w")

    # ── Avalanche section ─────────────────────────────────────────────

    def _avalanche_section(self):
        card = SectionCard(self, title="  Effet Avalanche — Démonstration",
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

        _btn(c, "Simuler altération", self._simulate_avalanche,
             T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER"), 180, 32
             ).grid(row=2, column=0, columnspan=2, pady=6, sticky="w")

        self.aval_canvas = tk.Canvas(c, height=26, bg=T.get("BG_DEEP"), highlightthickness=0)
        self.aval_canvas.grid(row=3, column=0, columnspan=2, pady=4, sticky="ew")

        aval_frame = ctk.CTkFrame(c, fg_color="transparent")
        aval_frame.grid(row=4, column=0, columnspan=2, pady=4, sticky="ew")
        aval_frame.grid_columnconfigure(0, weight=1)
        self.aval_result = TerminalBox(aval_frame, height=90)
        self.aval_result.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        ctk.CTkButton(aval_frame, text="Copier", command=lambda: self.aval_result.copy_to_clipboard(),
                      width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                      text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER")
                      ).grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")

    # ── Attack section ────────────────────────────────────────────────

    def _attack_section(self):
        card = SectionCard(self, title="  SIMULATION INTÉGRITÉ — Attaquant Hash",
                           accent=T.get("RED"), cia_keys=["I"])
        card.grid(row=4, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            c,
            text=("Jouez l'attaquant qui tente de modifier le message.\n"
                  "Objectif : observer si SHA-256 détecte la modification."),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        ctk.CTkLabel(c, text="Message utilisateur :", font=ctk.CTkFont(size=12),
                     text_color=T.get("TEXT_DIM")).grid(row=1, column=0, sticky="w")
        self.sim_hash_input = ctk.CTkTextbox(c, height=60, fg_color=T.get("BG_DEEP"),
                                              border_color=T.get("BORDER"), border_width=1)
        self.sim_hash_input.grid(row=2, column=0, pady=4, sticky="ew")

        step_frame = ctk.CTkFrame(c, fg_color="transparent")
        step_frame.grid(row=3, column=0, pady=4, sticky="w")
        _btn(step_frame, "Étape 1 : Hash original", self._sim_hash_step1,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 190, 30
             ).pack(side="left", padx=3)

        attack_frame = ctk.CTkFrame(c, fg_color="transparent")
        attack_frame.grid(row=4, column=0, pady=4, sticky="w")
        ctk.CTkLabel(attack_frame, text="Attaque :", font=ctk.CTkFont(size=12),
                     text_color=T.get("TEXT_DIM")).pack(side="left", padx=(0, 4))
        self.sim_hash_method = ctk.CTkOptionMenu(attack_frame, values=[
            "Modification d'un caractère",
            "Espace invisible",
            "Changement de casse",
            "Suppression d'un caractère",
            "Collision impossible SHA-256",
            "Length extension (concept)",
        ], width=210, fg_color=T.get("BG_HOVER"), button_color=T.get("RED_BORDER"),
           button_hover_color=T.get("RED_HOVER"), text_color=T.get("TEXT_DIM"),
           font=ctk.CTkFont(size=12))
        self.sim_hash_method.set("Modification d'un caractère")
        self.sim_hash_method.pack(side="left", padx=3)

        _btn(attack_frame, "Étape 2 : Attaquer", self._sim_hash_step2,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 130, 30
             ).pack(side="left", padx=3)
        _btn(attack_frame, "Nouvelle simulation", self._sim_hash_reset,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), 150, 30
             ).pack(side="left", padx=3)
        _btn(attack_frame, "Étape 3 : Vérifier", self._sim_hash_step3,
             T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 140, 30
             ).pack(side="left", padx=3)

        self.sim_hash_status = ctk.CTkLabel(c, text="Statut : prêt.",
                                             font=ctk.CTkFont(size=12), text_color=T.get("TEXT_DIM"))
        self.sim_hash_status.grid(row=5, column=0, pady=(2, 4), sticky="w")

        self.hash_compare = TerminalBox(c, height=120)
        self.hash_compare.grid(row=6, column=0, pady=4, sticky="ew")

        self.hash_result = StatusBar(c)
        self.hash_result.grid(row=7, column=0, pady=2, sticky="w")

        self._sim_hash_reset()

    # ── Timing Attack section ─────────────────────────────────────────

    def _timing_section(self):
        card = SectionCard(self, title="  TIMING ATTACK — Comparaison Naïve vs Temps-Constant",
                           accent=T.get("AMBER"), cia_keys=["I"])
        card.grid(row=5, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            c,
            text=(
                "Une comparaison naïve (==) s'arrête au 1er caractère différent.\n"
                "Un attaquant mesure le temps de réponse pour deviner combien de caractères correspondent\n"
                "et reconstitue progressivement un hash secret (token, password, MAC).\n"
                "hmac.compare_digest() compare TOUJOURS tous les caractères — timing constant."
            ),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        ctrl = ctk.CTkFrame(c, fg_color="transparent")
        ctrl.grid(row=1, column=0, pady=4, sticky="w")
        ctk.CTkLabel(ctrl, text="Itérations :", font=ctk.CTkFont(size=12),
                     text_color=T.get("TEXT_DIM")).pack(side="left", padx=(0, 4))
        self.timing_iter = ctk.CTkOptionMenu(
            ctrl, values=["10 000", "50 000", "100 000"],
            width=100, fg_color=T.get("BG_HOVER"), button_color=T.get("AMBER_BORDER"),
            button_hover_color=T.get("AMBER_HOVER"), text_color=T.get("TEXT_DIM"),
            font=ctk.CTkFont(size=12))
        self.timing_iter.set("50 000")
        self.timing_iter.pack(side="left", padx=3)
        _btn(ctrl, "Lancer benchmark", self._run_timing,
             T.get("AMBER_BG"), T.get("AMBER"), T.get("AMBER_BORDER"), T.get("AMBER_HOVER"), 160, 30
             ).pack(side="left", padx=8)

        self.timing_canvas = tk.Canvas(c, height=110, bg=T.get("BG_DEEP"), highlightthickness=0)
        self.timing_canvas.grid(row=2, column=0, pady=6, sticky="ew")

        timing_frame = ctk.CTkFrame(c, fg_color="transparent")
        timing_frame.grid(row=3, column=0, pady=4, sticky="ew")
        timing_frame.grid_columnconfigure(0, weight=1)
        self.timing_log = TerminalBox(timing_frame, height=140)
        self.timing_log.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        ctk.CTkButton(timing_frame, text="Copier", command=lambda: self.timing_log.copy_to_clipboard(),
                      width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                      text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER")
                      ).grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.timing_status = StatusBar(c)
        self.timing_status.grid(row=4, column=0, pady=2, sticky="w")

        self.timing_log.set_text(
            "Code VULNÉRABLE — short-circuit dès le 1er caractère différent :\n"
            "    if token_recu == token_secret:   # s'arrête immédiatement\n"
            "        grant_access()\n\n"
            "Code SÉCURISÉ — temps constant quelle que soit la position du mismatch :\n"
            "    import hmac\n"
            "    if hmac.compare_digest(token_recu, token_secret):\n"
            "        grant_access()\n\n"
            "→ Cliquez 'Lancer benchmark' pour mesurer la différence.\n"
            "→ Le graphique montre le timing (ns/op) selon la position du mismatch."
        )

    def _run_timing(self):
        self.timing_status.set("Benchmark en cours...", "loading")
        self.update()
        n_map = {"10 000": 10_000, "50 000": 50_000, "100 000": 100_000}
        N = n_map.get(self.timing_iter.get(), 50_000)

        def _worker():
            target     = "a" * 64
            positions  = [0, 8, 16, 24, 32, 40, 48, 56, 63]
            res_naive  = []
            res_hmac   = []

            for pos in positions:
                candidate = ("x" + "a" * 63) if pos == 0 else ("a" * pos + "x" + "a" * (63 - pos))

                t0 = time.perf_counter_ns()
                for _ in range(N):
                    _ = (target == candidate)
                res_naive.append((time.perf_counter_ns() - t0) / N)

                t0 = time.perf_counter_ns()
                for _ in range(N):
                    _ = _hmac_mod.compare_digest(target, candidate)
                res_hmac.append((time.perf_counter_ns() - t0) / N)

            self.after(0, lambda: self._show_timing(positions, res_naive, res_hmac, N))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_timing(self, positions, res_naive, res_hmac, N):
        cv = self.timing_canvas
        cv.delete("all")
        self.update_idletasks()
        W = cv.winfo_width() or 700
        H, ml, mr, mt, mb = 110, 40, 20, 10, 28
        n      = len(positions)
        gw     = (W - ml - mr) / n
        bw     = gw * 0.36
        max_t  = max(max(res_naive), max(res_hmac), 0.01)
        plot_h = H - mt - mb

        for i, pos in enumerate(positions):
            gx     = ml + i * gw
            y_base = H - mb
            h_n = int((res_naive[i] / max_t) * plot_h)
            h_h = int((res_hmac[i]  / max_t) * plot_h)
            cv.create_rectangle(gx,        y_base - h_n, gx + bw,        y_base, fill=T.get("AMBER"),  outline="")
            cv.create_rectangle(gx + bw + 2, y_base - h_h, gx + bw*2 + 2, y_base, fill=T.get("TEAL"), outline="")
            cv.create_text(gx + bw, H - 14, text=str(pos), fill=T.get("TEXT_DIM"),
                            font=("Courier", 7), anchor="center")

        cv.create_text(ml, H - 4, text="position mismatch →",
                       fill=T.get("TEXT_DIM"), font=("Courier", 7), anchor="w")
        for color, label, x in [(T.get("AMBER"), "== (naïf)", W - 190),
                                 (T.get("TEAL"),  "hmac.compare_digest", W - 115)]:
            cv.create_rectangle(x, 4, x + 12, 14, fill=color, outline="")
            cv.create_text(x + 16, 9, text=label, fill=color, font=("Courier", 8), anchor="w")

        r_n = max(res_naive) - min(res_naive)
        r_h = max(res_hmac)  - min(res_hmac)
        lines = [
            f"TIMING BENCHMARK ({N:,} itérations · position = index du 1er char différent)\n",
            f"{'pos':<5} {'== naïf (ns/op)':>18} {'hmac (ns/op)':>14} {'diff (ns)':>12}",
            "─" * 54,
        ]
        for i, pos in enumerate(positions):
            lines.append(f"  {pos:<3}   {res_naive[i]:>15.1f}   {res_hmac[i]:>11.1f}   {res_naive[i]-res_hmac[i]:>+9.1f}")
        lines += [
            "─" * 54,
            f"range == (max-min) : {r_n:.1f} ns  ← variance = fuite timing potentielle",
            f"range hmac         : {r_h:.1f} ns  ← quasi-constant (résistant)",
            "",
            "CONCLUSION : Utilisez hmac.compare_digest() pour toute comparaison de secret.",
            "Impacts réels : tokens JWT, cookies session, HMAC, mots de passe hachés.",
        ]
        self.timing_log.set_text("\n".join(lines))
        self.timing_status.set(f"Benchmark terminé — {N:,} itérations, {len(positions)} points de mismatch.", "ok")

    # ── MITM section ──────────────────────────────────────────────────

    _MITM_KEY = b"secret_key_alice_bob_only"

    def _mitm_section(self):
        card = SectionCard(self, title="  SIMULATION MITM — Man-in-the-Middle Complet",
                           accent=T.get("RED"), cia_keys=["I"])
        card.grid(row=6, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            c,
            text=(
                "Démontre la différence entre Hash seul et HMAC face à Mallory (Man-in-the-Middle).\n"
                "Mode Hash seul : SHA-256 est public → Mallory recalcule un hash valide → Bob est trompé.\n"
                "Mode HMAC : sans la clé secrète → Mallory ne peut pas forger → Bob détecte le tampering."
            ),
            font=ctk.CTkFont(size=13), text_color=T.get("TEXT_DIM"), wraplength=760, justify="left",
        ).grid(row=0, column=0, pady=(0, 8), sticky="w")

        mode_frame = ctk.CTkFrame(c, fg_color="transparent")
        mode_frame.grid(row=1, column=0, pady=4, sticky="w")
        ctk.CTkLabel(mode_frame, text="Mode :", font=ctk.CTkFont(size=12),
                     text_color=T.get("TEXT_DIM")).pack(side="left", padx=(0, 4))
        self.mitm_mode = ctk.CTkOptionMenu(
            mode_frame, values=["Hash seul — SHA-256 (vulnérable)", "HMAC-SHA256 (sécurisé)"],
            width=260, fg_color=T.get("BG_HOVER"), button_color=T.get("RED_BORDER"),
            button_hover_color=T.get("RED_HOVER"), text_color=T.get("TEXT_DIM"),
            font=ctk.CTkFont(size=12))
        self.mitm_mode.set("Hash seul — SHA-256 (vulnérable)")
        self.mitm_mode.pack(side="left", padx=3)

        ctk.CTkLabel(c, text="Message d'Alice :", font=ctk.CTkFont(size=12),
                     text_color=T.get("TEXT_DIM")).grid(row=2, column=0, pady=(8, 2), sticky="w")
        self.mitm_input = ctk.CTkTextbox(c, height=50, fg_color=T.get("BG_DEEP"),
                                          border_color=T.get("BORDER"), border_width=1)
        self.mitm_input.grid(row=3, column=0, pady=4, sticky="ew")
        self.mitm_input.insert("0.0", "Virement validé — montant: 1 000 EUR → compte FR76 1234 5678")

        btn_frame = ctk.CTkFrame(c, fg_color="transparent")
        btn_frame.grid(row=4, column=0, pady=4, sticky="w")
        _btn(btn_frame, "1. Alice envoie",      self._mitm_step1,
             T.get("BLUE_BG"), T.get("BLUE"), T.get("BLUE_BORDER"), T.get("BLUE_HOVER"), 155, 32).pack(side="left", padx=3)
        _btn(btn_frame, "2. Mallory intercepte", self._mitm_step2,
             T.get("RED_BG"), T.get("RED"), T.get("RED_BORDER"), T.get("RED_HOVER"), 175, 32).pack(side="left", padx=3)
        _btn(btn_frame, "3. Bob vérifie",        self._mitm_step3,
             T.get("GREEN_BG"), T.get("GREEN"), T.get("GREEN_BORDER"), T.get("GREEN_HOVER"), 140, 32).pack(side="left", padx=3)
        _btn(btn_frame, "Réinitialiser",         self._mitm_reset,
             T.get("BG_HOVER"), T.get("TEXT_DIM"), T.get("BORDER"), T.get("CYAN_HOVER"), 120, 32).pack(side="left", padx=3)

        mitm_frame = ctk.CTkFrame(c, fg_color="transparent")
        mitm_frame.grid(row=5, column=0, pady=4, sticky="ew")
        mitm_frame.grid_columnconfigure(0, weight=1)
        self.mitm_log = TerminalBox(mitm_frame, height=200)
        self.mitm_log.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        ctk.CTkButton(mitm_frame, text="Copier", command=lambda: self.mitm_log.copy_to_clipboard(),
                      width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                      text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER")
                      ).grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.mitm_status = StatusBar(c)
        self.mitm_status.grid(row=6, column=0, pady=2, sticky="w")

        self._mitm_reset()

    def _mitm_reset(self):
        self._mitm_step     = 0
        self._mitm_msg      = ""
        self._mitm_auth     = ""
        self._mitm_tampered = ""
        self._mitm_forged   = ""
        self.mitm_log.set_text(
            "Simulation MITM prête.\n\n"
            "Scénario :\n"
            "  Alice ──── (message + auth) ───→ [Mallory] ──── (forgé) ───→ Bob\n\n"
            "→ Sélectionnez un mode et cliquez 'Alice envoie'."
        )
        self.mitm_status.clear()

    def _mitm_step1(self):
        import hashlib
        msg = self.mitm_input.get("0.0", "end").strip()
        if not msg:
            self.mitm_status.set("Message vide.", "error")
            return
        self._mitm_msg  = msg
        mode = self.mitm_mode.get()

        if "HMAC" in mode:
            auth  = _hmac_mod.new(self._MITM_KEY, msg.encode(), digestmod="sha256").hexdigest()
            label = "HMAC-SHA256"
            key_info = (
                f"Clé secrète partagée : {self._MITM_KEY.decode()!r}\n"
                "(échangée préalablement via canal sécurisé — inconnue de Mallory)"
            )
        else:
            auth  = hashlib.sha256(msg.encode()).hexdigest()
            label = "SHA-256"
            key_info = (
                "Aucune clé secrète — SHA-256 est une fonction PUBLIQUE.\n"
                "N'importe qui peut calculer SHA256(n'importe_quel_message)."
            )

        self._mitm_auth = auth
        self._mitm_step = 1
        self.mitm_log.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  ÉTAPE 1 — Alice compose et envoie son message          ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"Message    : {msg!r}\n"
            f"Protection : {label}\n"
            f"{key_info}\n\n"
            f"{label}(message) :\n  {auth}\n\n"
            f"Paquet envoyé sur le réseau :\n"
            f"  [ msg='{msg[:55]}'\n"
            f"    {label}='{auth[:48]}...' ]\n\n"
            "→ Le paquet transite. Mallory est positionnée en MITM.\n"
            "→ Cliquez 'Mallory intercepte'."
        )
        self.mitm_status.set(f"Alice a envoyé le paquet avec {label}.", "ok")

    def _mitm_step2(self):
        import hashlib
        if self._mitm_step < 1:
            self.mitm_status.set("Faites d'abord l'étape 1.", "warning")
            return

        mode     = self.mitm_mode.get()
        original = self._mitm_msg
        tampered = (original
                    .replace("1 000",  "99 000")
                    .replace("validé", "ANNULÉ")
                    .replace("→",      "← Attaquant"))
        if tampered == original:
            tampered = original + " [FALSIFIÉ PAR MALLORY]"
        self._mitm_tampered = tampered

        if "HMAC" in mode:
            wrong_key      = b"wrong_guess"
            fake           = _hmac_mod.new(wrong_key, tampered.encode(), digestmod="sha256").hexdigest()
            self._mitm_forged = fake
            capability = (
                "Mallory tente de forger le HMAC avec une clé devinée :\n"
                f"  HMAC(clé_devinée={wrong_key!r}, msg_falsifié)\n"
                f"  = {fake}\n\n"
                f"⚠️  La vraie clé est {self._MITM_KEY.decode()!r}.\n"
                "    Mallory ne la connaît pas → son HMAC est incorrect.\n"
                "    Bob recalculera HMAC(vraie_clé, msg) → MISMATCH."
            )
        else:
            forged         = hashlib.sha256(tampered.encode()).hexdigest()
            self._mitm_forged = forged
            capability = (
                "SHA-256 est public — Mallory recalcule librement :\n"
                f"  SHA256(msg_falsifié)\n"
                f"  = {forged}\n\n"
                "✅  Mallory a un hash 'valide' pour son message forgé !\n"
                "    Elle remplace le hash original par ce nouveau hash.\n"
                "    Bob recevra un paquet cohérent → il sera TROMPÉ."
            )

        self._mitm_step = 2
        self.mitm_log.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  ÉTAPE 2 — Mallory intercepte et falsifie               ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"Original : {original!r}\n"
            f"Falsifié : {tampered!r}\n\n"
            f"{capability}\n\n"
            f"Paquet forgé envoyé à Bob :\n"
            f"  [ msg='{tampered[:55]}'\n"
            f"    auth='{self._mitm_forged[:48]}...' ]\n\n"
            "→ Cliquez 'Bob vérifie'."
        )
        self.mitm_status.set("Mallory a intercepté et falsifié le paquet.", "warning")

    def _mitm_step3(self):
        import hashlib
        if self._mitm_step < 2:
            self.mitm_status.set("Faites d'abord les étapes 1 et 2.", "warning")
            return

        mode     = self.mitm_mode.get()
        tampered = self._mitm_tampered

        if "HMAC" in mode:
            bob_auth = _hmac_mod.new(self._MITM_KEY, tampered.encode(), digestmod="sha256").hexdigest()
            match    = _hmac_mod.compare_digest(bob_auth, self._mitm_forged)
            icon     = "✅  TAMPERING DÉTECTÉ — Bob rejette !" if not match else "⚠️  Inattendu"
            level    = "ok" if not match else "error"
            detail   = (
                f"Bob recalcule HMAC(vraie_clé, msg_reçu) :\n  {bob_auth}\n"
                f"HMAC reçu de Mallory :\n  {self._mitm_forged}\n\n"
                + ("→ DIFFÉRENTS — Bob sait que le message a été altéré en transit.\n"
                   "→ Mallory sans clé secrète = impossible de forger un HMAC valide."
                   if not match else "Collision HMAC inattendue.")
            )
        else:
            bob_hash = hashlib.sha256(tampered.encode()).hexdigest()
            match    = (bob_hash == self._mitm_forged)
            icon     = "⚠️  ATTAQUE RÉUSSIE — Bob est trompé !" if match else "✅  Intégrité OK"
            level    = "error" if match else "ok"
            detail   = (
                f"Bob recalcule SHA256(msg_reçu) :\n  {bob_hash}\n"
                f"Hash reçu de Mallory :\n  {self._mitm_forged}\n\n"
                + ("→ IDENTIQUES — Bob croit que le message est intact. C'est FAUX.\n"
                   "→ SHA-256 seul NE PROUVE PAS l'origine — n'importe qui peut le calculer."
                   if match else "→ Différents — message non altéré.")
            )

        self.mitm_log.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            f"║  ÉTAPE 3 — VERDICT BOB : {'HMAC-SHA256' if 'HMAC' in mode else 'Hash seul (SHA-256)':<28}║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"{icon}\n\n"
            f"{detail}\n\n"
            "─" * 54 + "\n"
            "LEÇON :\n"
            "  • SHA-256 seul       → intégrité SANS authentification\n"
            "    (Mallory recalcule n'importe quel hash librement)\n\n"
            "  • HMAC-SHA256(clé)   → intégrité + authentification\n"
            "    (sans la clé secrète, Mallory ne peut pas forger)\n\n"
            "  • Signature RSA-PSS  → authentification + non-répudiation\n"
            "    (pas de clé partagée requise — clé publique suffit)"
        )
        self.mitm_status.set(
            "Attaque réussie — hash seul insuffisant." if level == "error"
            else "Attaque bloquée — HMAC a tenu.", level)
        self._mitm_step = 3

    # ── Attack simulation handlers ─────────────────────────────────────

    def _set_hash_status(self, text, level="info"):
        color = {"ok": T.get("GREEN"), "error": T.get("RED"),
                 "warning": T.get("AMBER")}.get(level, T.get("TEXT_DIM"))
        self.sim_hash_status.configure(text=f"Statut : {text}", text_color=color)

    def _sim_hash_reset(self):
        self._sim_hash_plain  = ""
        self._sim_hash_orig   = ""
        self._sim_hash_target = ""
        self._sim_hash_step   = 0
        self.sim_hash_input.delete("0.0", "end")
        self.hash_compare.clear()
        self.hash_result.clear()
        self._set_hash_status("Prêt pour nouvelle simulation.", "info")

    def _sim_hash_step1(self):
        msg = self.sim_hash_input.get("0.0", "end").strip()
        if not msg:
            self._set_hash_status("Message vide. Saisissez du texte.", "error")
            return
        self._sim_hash_plain = msg
        self._sim_hash_orig  = self.hm.hash_text(msg)
        self._sim_hash_step  = 1
        h = self._sim_hash_orig
        h_visual = "  ".join(h[i:i+8] for i in range(0, 64, 8))
        self.hash_compare.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  ÉTAPE 1 — Le destinataire calcule et publie le hash.   ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"Message original    : {msg!r}\n"
            f"Longueur            : {len(msg)} caractères → {len(msg.encode('utf-8'))} octets\n\n"
            f"SHA-256 (64 hex)    : {self._sim_hash_orig}\n"
            f"Découpage 8-chars   :\n  {h_visual}\n\n"
            "→ Ce hash est distribué publiquement (ou stocké en base).\n"
            "→ L'attaquant tente de modifier le message SANS changer le hash."
        )
        self._set_hash_status("Étape 1 terminée — hash calculé. Choisissez une attaque.", "ok")

    def _sim_hash_step2(self):
        if self._sim_hash_step < 1:
            self._set_hash_status("Faites d'abord l'étape 1.", "warning")
            return
        choice = self.sim_hash_method.get()
        base   = self._sim_hash_plain

        if choice == "Modification d'un caractère":
            new_ch = "X" if not base.endswith("X") else "Y"
            self._sim_hash_target = base[:-1] + new_ch
            technique = (
                f"Modification : position {len(base)-1} : {base[-1]!r} → {new_ch!r}\n"
                "Impact visuel : presque identique — l'œil humain ne détecte rien.\n"
                "Impact cryptographique : ~50% du hash change (effet avalanche).\n\n"
                "Cas réel : falsification d'un montant, d'un nom, d'une date."
            )
        elif choice == "Espace invisible":
            self._sim_hash_target = base + "\u200b"
            technique = (
                "Ajout d'un ZERO WIDTH SPACE (U+200B) en fin de message.\n"
                "Invisible à l'affichage — indétectable visuellement.\n\n"
                "Cas réel : phishing — 'paypal.com\u200b' ≠ 'paypal.com'.\n"
                "SHA-256 détecte toujours la différence."
            )
        elif choice == "Changement de casse":
            self._sim_hash_target = base.swapcase()
            diffs = [(i, base[i], base.swapcase()[i])
                     for i in range(len(base)) if base[i] != base.swapcase()[i]]
            diff_str = ", ".join(f"pos {i}: {o!r}→{n!r}" for i, o, n in diffs[:5])
            technique = (
                f"Inversion de casse sur {len(diffs)} caractère(s) : {diff_str}\n\n"
                "Cas réel : 'VALIDE' et 'valide' ont même sens mais hash totalement différent.\n"
                "SHA-256 distingue toujours majuscules et minuscules."
            )
        elif choice == "Suppression d'un caractère":
            self._sim_hash_target = base[:-1] if len(base) > 1 else ""
            technique = (
                f"Suppression du dernier caractère : {base[-1]!r}\n"
                f"Longueur : {len(base)} → {len(self._sim_hash_target)} caractères\n\n"
                "Cas réel : troncature d'un montant — 'pour 1000€' → 'pour 1000'\n"
                "SHA-256 détecte immédiatement : hashes complètement différents."
            )
        elif choice == "Collision impossible SHA-256":
            self._sim_hash_target = base
            technique = (
                "CONTEXTE : collision = M2 ≠ M1 tel que SHA256(M1) = SHA256(M2)\n\n"
                "SHA-256 → 2^256 ≈ 10^77 valeurs possibles.\n"
                "Meilleure attaque (Birthday) : ~2^128 essais.\n"
                "Réseau Bitcoin : ~10^21 hash/s → temps collision ~10^18 ans.\n\n"
                "SHA-1 cassé en 2017 (Google SHAttered) : 110 GPU-années.\n"
                "SHA-256 : aucune collision connue. Standard NIST actif.\n\n"
                "DÉMONSTRATION : même message → même hash (pas de collision)."
            )
        elif choice == "Length extension (concept)":
            self._sim_hash_target = base + "ajout_attaquant"
            technique = (
                "ATTAQUE LENGTH EXTENSION (contre MAC = SHA256(secret || message)) :\n\n"
                "Connaissant SHA256(secret || message), un attaquant peut calculer\n"
                "SHA256(secret || message || padding || extra) SANS connaître 'secret'.\n"
                "Exploite la structure interne Merkle-Damgård de SHA-256.\n\n"
                "Exploitable sur SHA-256, SHA-1, MD5 utilisés naïvement comme MAC.\n"
                "MITIGATION : HMAC-SHA256 — immune par construction."
            )
        else:
            self._set_hash_status("Attaque inconnue.", "error")
            return

        new_hash = self.hm.hash_text(self._sim_hash_target)
        diff = sum(a != b for a, b in zip(self._sim_hash_orig, new_hash))
        self._sim_hash_step = 2
        self.hash_compare.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            f"║  ÉTAPE 2 — Attaque : {choice:<35}║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"{technique}\n\n"
            "─" * 54 + "\n"
            f"Message modifié  : {self._sim_hash_target!r}\n"
            f"Hash modifié     : {new_hash}\n"
            f"Chars différents : {diff}/64 ({diff/64*100:.1f}% du hash)"
        )
        self._set_hash_status("Étape 2 terminée — passez à l'étape 3.", "ok")

    def _sim_hash_step3(self):
        if self._sim_hash_step < 2:
            self._set_hash_status("Exécutez les étapes 1 et 2 d'abord.", "warning")
            return
        hash2     = self.hm.hash_text(self._sim_hash_target)
        diff      = sum(a != b for a, b in zip(self._sim_hash_orig, hash2))
        same      = self._sim_hash_orig == hash2
        same_text = self._sim_hash_plain == self._sim_hash_target

        if same and same_text:
            badge   = "🟢 MÊME MESSAGE — Intégrité confirmée"
            level   = "ok"
            verdict = "Le message n'a pas été modifié.\nSHA-256 est déterministe — même entrée, même sortie."
        elif same and not same_text:
            badge   = "🔴 COLLISION DÉTECTÉE — DANGER CRITIQUE"
            level   = "error"
            verdict = "Deux messages différents → même hash. En pratique IMPOSSIBLE avec SHA-256."
        else:
            badge   = "✅ MODIFICATION DÉTECTÉE — SHA-256 a fonctionné"
            level   = "ok"
            verdict = (
                f"Différence : {diff}/64 caractères hex ({diff/64*100:.1f}%)\n"
                "L'effet avalanche garantit qu'aucune modification ne passe inaperçue.\n\n"
                "Un attaquant NE PEUT PAS modifier le message et conserver le même hash.\n"
                "→ Si vous vérifiez le hash de référence, vous êtes protégé."
            )

        h1       = self._sim_hash_orig
        diff_vis = "".join("^" if a != b else " " for a, b in zip(h1, hash2))
        self.hash_result.set(f"{badge}  •  Δ = {diff}/64 chars")
        self.hash_compare.set_text(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  ÉTAPE 3 — VERDICT FINAL                                ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            f"Message original : {self._sim_hash_plain!r}\n"
            f"Message modifié  : {self._sim_hash_target!r}\n\n"
            f"Hash original    : {h1}\n"
            f"Hash modifié     : {hash2}\n"
            f"Différences      : {diff_vis}\n\n"
            f"{verdict}"
        )
        self._set_hash_status(f"Étape 3 terminée — {diff} char(s) différent(s).", level)

    # ── Live hash handlers ────────────────────────────────────────────

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
            changed = old_h is None or (old_h and old_h[i] != ch)
            color = T.get("AMBER") if changed else T.get("TEAL_BG")
            x0 = i * cw
            cv.create_rectangle(x0, 2, x0 + cw - 1, 16, fill=color, outline="")
            if cw > 9:
                cv.create_text(x0 + cw / 2, 9, text=ch, font=("Courier", 7),
                                fill=T.get("TEXT_CODE"))

    def _hash_text(self):
        try:
            text = self.live_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Texte vide.")
            self.live_hash_lbl.configure(text=self.hm.hash_text(text))
            self.live_status.set("SHA-256 calculé — 256 bits / 64 chars hex", "ok")
        except Exception as e:
            self.live_status.set(str(e), "error")

    def _hash_file(self):
        try:
            path = filedialog.askopenfilename()
            if not path:
                return
            self.live_hash_lbl.configure(text=self.hm.hash_file(path))
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

    def _hash_clear(self):
        self.live_input.delete("0.0", "end")
        self.live_hash_lbl.configure(text="")
        self.live_len_lbl.configure(text="")
        self.live_status.clear()

    def _use_ref(self):
        if self._ref_hash:
            self.verify_ref.delete(0, "end")
            self.verify_ref.insert(0, self._ref_hash)

    def _verify(self):
        try:
            text = self.verify_input.get("0.0", "end").strip()
            ref  = self.verify_ref.get().strip()
            if not text or not ref:
                raise ValueError("Texte et hash requis.")
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

    # ── Avalanche handlers ────────────────────────────────────────────

    def _simulate_avalanche(self):
        original = self.aval_input.get("0.0", "end").strip()
        if not original:
            return
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
            f"Effet avalanche  : {'EXCELLENT ✅' if pct > 40 else 'PARTIEL'}"
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
