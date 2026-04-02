import customtkinter as ctk
import threading

from core.performance import PerformanceAnalyzer
import gui.theme as T

from gui.widgets import CIABadge, TerminalBox, SectionCard, StatusBar

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MPL = True
except ImportError:
    MPL = False


class PerformancePage(ctk.CTkScrollableFrame):

    INFO = (
        "Comparaison des performances : AES-256-CBC (symétrique) vs RSA-2048 (asymétrique).\n"
        "Résultat typique : AES est ~300-500× plus rapide. La génération de clé RSA (multiplication "
        "de grands premiers) est l'opération la plus coûteuse.\n"
        "Conclusion : on utilise RSA uniquement pour l'échange de la clé AES — c'est le principe de TLS, PGP, SSH."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color=T.get("BG_DEEP"), scrollbar_button_color=T.get("BORDER"))
        self.grid_columnconfigure(0, weight=1)
        self.pa      = PerformanceAnalyzer()
        self._res    = None
        self._canvas = None
        self._build()

    def _build(self):
        self._header()
        self._control_section()
        self._results_section()
        self._chart_section()
        self._conclusion_section()

    def _header(self):
        f = ctk.CTkFrame(self, fg_color=T.get("BG_CARD"), corner_radius=8,
                         border_width=1, border_color=T.get("BORDER"))
        f.grid(row=0, column=0, padx=14, pady=(14, 6), sticky="ew")
        f.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="⚡  COMPARAISON DES PERFORMANCES",
                     font=ctk.CTkFont(family="Courier", size=15, weight="bold"),
                     text_color=T.get("CYAN")).grid(row=0, column=0, sticky="w")
        CIABadge(top, ["C", "I", "A"]).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(f, text=self.INFO, font=ctk.CTkFont(size=13),
                     text_color=T.get("TEXT_DIM"), wraplength=820, justify="left",
                     ).grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")

    def _control_section(self):
        card = SectionCard(self, title="  ▶  Paramètres du Benchmark", accent=T.get("CYAN"))
        card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(c, text="Message test :",
                     font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                     text_color=T.get("CYAN")).grid(row=0, column=0, padx=(0, 8), pady=6, sticky="w")
        self.msg_entry = ctk.CTkEntry(c, fg_color=T.get("BG_DEEP"), border_color=T.get("BORDER"), text_color=T.get("TEXT_CODE"))
        self.msg_entry.insert(0, "Message de test benchmark cryptographique ENSAF 2024")
        self.msg_entry.grid(row=0, column=1, padx=4, pady=6, sticky="ew")

        self.run_btn = ctk.CTkButton(
            c, text="▶  Lancer le benchmark", width=210, height=36,
            fg_color=T.get("CYAN_BG"), hover_color=T.get("CYAN_HOVER"),
            text_color=T.get("CYAN"), border_width=1, border_color=T.get("CYAN_BORDER"),
            command=self._run,
        )
        self.run_btn.grid(row=1, column=0, columnspan=2, pady=8, sticky="w")
        self.ctrl_status = StatusBar(c)
        self.ctrl_status.grid(row=2, column=0, columnspan=2, pady=2, sticky="w")

    def _results_section(self):
        card = SectionCard(self, title="  Résultats Numériques", accent=T.get("BLUE"))
        card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        self.result_box = TerminalBox(c, height=200)
        result_frame = ctk.CTkFrame(c, fg_color="transparent")
        result_frame.grid(row=0, column=0, pady=4, sticky="ew")
        result_frame.grid_columnconfigure(0, weight=1)
        self.result_box = TerminalBox(result_frame, height=200)
        self.result_box.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(result_frame, text="Copier", command=lambda: self.result_box.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.result_box.set_text("Les résultats s'afficheront ici après le benchmark.")

    def _chart_section(self):
        if not MPL: return
        card = SectionCard(self, title="  Graphique Comparatif", accent=T.get("PURPLE"))
        card.grid(row=3, column=0, padx=14, pady=6, sticky="ew")
        self._chart_parent = card.content
        self._chart_parent.grid_columnconfigure(0, weight=1)

    def _conclusion_section(self):
        card = SectionCard(self, title="  Analyse Académique", accent=T.get("GREEN"))
        card.grid(row=4, column=0, padx=14, pady=(6, 14), sticky="ew")
        c = card.content
        c.grid_columnconfigure(0, weight=1)
        self.concl_box = TerminalBox(c, height=160)
        concl_frame = ctk.CTkFrame(c, fg_color="transparent")
        concl_frame.grid(row=0, column=0, pady=4, sticky="ew")
        concl_frame.grid_columnconfigure(0, weight=1)
        self.concl_box = TerminalBox(concl_frame, height=160)
        self.concl_box.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="ew")
        copy_btn = ctk.CTkButton(concl_frame, text="Copier", command=lambda: self.concl_box.copy_to_clipboard(),
                                 width=70, height=30, fg_color=T.get("BG_HOVER"), hover_color=T.get("CYAN_HOVER"),
                                 text_color=T.get("TEXT_DIM"), border_width=1, border_color=T.get("BORDER"))
        copy_btn.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="e")
        self.concl_box.set_text(
            "L'analyse académique s'affichera après le benchmark.\n\n"
            "Points couverts :\n"
            "  • Pourquoi AES est plus rapide que RSA\n"
            "  • Justification mathématique du coût RSA\n"
            "  • Recommandation : chiffrement hybride")

    # ── Run ───────────────────────────────────────────────────────────

    def _run(self):
        self.run_btn.configure(state="disabled", text="En cours...")
        self.ctrl_status.set("AES : 100 itérations · RSA : 5 itérations...", "loading")
        self.update()
        threading.Thread(target=self._thread, daemon=True).start()

    def _thread(self):
        try:
            text = self.msg_entry.get().strip() or "benchmark"
            self._res = self.pa.full_comparison(text)
            self.after(0, self._done)
        except Exception as e:
            self.after(0, lambda: self.ctrl_status.set(str(e), "error"))
            self.after(0, lambda: self.run_btn.configure(
                state="normal", text="▶  Lancer le benchmark"))

    def _done(self):
        r = self._res
        self.result_box.set_text(self.pa.format_report(r))
        self.ctrl_status.set(
            f"Terminé — AES ~{r['speedup_factor']}× plus rapide que RSA.", "ok")
        self.run_btn.configure(state="normal", text="▶  Lancer le benchmark")

        aes, rsa = r["aes"], r["rsa"]
        concl = (
            f"ANALYSE — AES-256-CBC vs RSA-2048\n{'─'*46}\n\n"
            f"1. GÉNÉRATION DE CLÉ\n"
            f"   AES : {aes['keygen_ms']:.4f} ms  vs  RSA : {rsa['keygen_ms']:.2f} ms\n"
            f"   RSA génère deux nombres premiers de ~1024 bits chacun.\n"
            f"   AES appelle os.urandom() — entropie OS, quasi-instantané.\n\n"
            f"2. CHIFFREMENT\n"
            f"   AES : {aes['encrypt_ms']:.4f} ms  vs  RSA : {rsa['encrypt_ms']:.4f} ms\n"
            f"   AES opère sur des blocs de 128 bits avec XOR + substitutions.\n"
            f"   RSA calcule ct = m^e mod n (exponentiation modulaire coûteuse).\n\n"
            f"3. CONCLUSION\n"
            f"   Facteur : AES ≈ {r['speedup_factor']}× plus rapide que RSA.\n"
            f"   Solution : AES chiffre les données, RSA chiffre la clé AES.\n"
            f"   C'est exactement le schéma TLS 1.3 utilisé dans HTTPS."
        )
        self.concl_box.set_text(concl)

        if MPL:
            self._draw_chart()

    def _draw_chart(self):
        r   = self._res
        aes = r["aes"]
        rsa = r["rsa"]

        if self._canvas:
            self._canvas.get_tk_widget().destroy()

        fig = Figure(figsize=(7.5, 3.4), dpi=96, facecolor=T.get("BG_DEEP"))
        ax  = fig.add_subplot(111, facecolor=T.get("BG_CARD"))

        cats = ["Génération\nde clé", "Chiffrement", "Déchiffrement", "TOTAL"]
        av   = [aes["keygen_ms"], aes["encrypt_ms"], aes["decrypt_ms"], aes["total_ms"]]
        rv   = [rsa["keygen_ms"], rsa["encrypt_ms"], rsa["decrypt_ms"], rsa["total_ms"]]

        x, w = range(len(cats)), 0.35
        b1 = ax.bar([i - w/2 for i in x], av, w, label="AES-256-CBC", color=T.get("BLUE"), alpha=0.88)
        b2 = ax.bar([i + w/2 for i in x], rv, w, label="RSA-2048",    color=T.get("PURPLE"), alpha=0.88)

        for bar, vals in [(b1, av), (b2, rv)]:
            for b, v in zip(bar, vals):
                ax.text(b.get_x() + b.get_width()/2, b.get_height() + max(rv)*0.01,
                        f"{v:.2f}", ha="center", va="bottom",
                        fontsize=8, color="#e8f4fd", fontfamily="Courier")

        ax.set_xticks(list(x))
        ax.set_xticklabels(cats, color=T.get("TEXT_DIM"), fontsize=9, fontfamily="Courier")
        ax.set_ylabel("Temps (ms)", color=T.get("TEXT_DIM"), fontsize=12)
        ax.set_title(f"AES-256-CBC vs RSA-2048  —  Facteur ×{r['speedup_factor']}",
                     color=T.get("CYAN"), fontsize=12, fontweight="bold", fontfamily="Courier")
        ax.tick_params(colors=T.get("TEXT_DIM"))
        for spine in ax.spines.values():
            spine.set_color(T.get("BORDER"))
        ax.legend(facecolor=T.get("BG_CARD"), labelcolor=T.get("TEXT_DIM"), edgecolor=T.get("BORDER"), fontsize=12)
        ax.set_facecolor(T.get("BG_CARD"))
        fig.tight_layout(pad=1.5)

        self._canvas = FigureCanvasTkAgg(fig, master=self._chart_parent)
        self._canvas.draw()
        self._canvas.get_tk_widget().grid(row=0, column=0, sticky="ew", pady=4)
