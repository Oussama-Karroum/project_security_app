"""
Module: performance_page.py
Role:   GUI page for AES vs RSA performance comparison with bar chart
        Calls core.performance — zero crypto code here
"""

import customtkinter as ctk
import threading
from core.performance import PerformanceAnalyzer

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class PerformancePage(ctk.CTkFrame):
    """
    Performance page — benchmark AES vs RSA, display results + bar chart.

    CIA Objective : (Transversal — illustrates why hybrid encryption is used)
    """

    INFO_TEXT = (
        "⚡  COMPARAISON DES PERFORMANCES\n\n"
        "Cette page compare les temps d'exécution de AES-256-CBC (symétrique) vs RSA-2048 (asymétrique).\n\n"
        "• AES est optimisé pour le traitement de données volumineuses.\n"
        "• RSA est mathématiquement coûteux — particulièrement pour la génération de clés.\n"
        "• Résultat attendu : AES est plusieurs centaines de fois plus rapide que RSA.\n"
        "• Conclusion pratique : On utilise RSA uniquement pour échanger la clé AES (chiffrement hybride)."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.analyzer = PerformanceAnalyzer()
        self._results  = None

        self._build_info_banner()
        self._build_main()

    def _build_info_banner(self):
        banner = ctk.CTkTextbox(self, height=120, wrap="word", font=ctk.CTkFont(size=12))
        banner.insert("0.0", self.INFO_TEXT)
        banner.configure(state="disabled")
        banner.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, padx=16, pady=(0,16), sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # Controls
        ctrl = ctk.CTkFrame(main)
        ctrl.grid(row=0, column=0, pady=8, sticky="ew")
        ctrl.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(ctrl, text="Message de test :", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=10, pady=8, sticky="w")
        self.test_msg = ctk.CTkEntry(ctrl, width=320,
                                     placeholder_text="Texte utilisé pour le benchmark")
        self.test_msg.insert(0, "Message de test pour benchmark cryptographique ENSAF 2024")
        self.test_msg.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        self.run_btn = ctk.CTkButton(ctrl, text="▶  Lancer le benchmark",
                                     command=self._run_benchmark, height=36, width=180)
        self.run_btn.grid(row=0, column=2, padx=8, pady=8)

        self.bench_status = ctk.CTkLabel(ctrl, text="", font=ctk.CTkFont(size=12))
        self.bench_status.grid(row=1, column=0, columnspan=3, padx=10, pady=(0,6), sticky="w")

        # Results text
        self.result_box = ctk.CTkTextbox(main, height=200,
                                          font=ctk.CTkFont(family="Courier", size=12))
        self.result_box.grid(row=1, column=0, pady=(0, 8), sticky="ew")
        self.result_box.insert("0.0", "Les résultats s'afficheront ici après le benchmark.")
        self.result_box.configure(state="disabled")

        # Chart area
        if MATPLOTLIB_AVAILABLE:
            self.chart_frame = ctk.CTkFrame(main)
            self.chart_frame.grid(row=2, column=0, sticky="nsew")
            self.chart_frame.grid_columnconfigure(0, weight=1)
            self.chart_frame.grid_rowconfigure(0, weight=1)
            self._canvas = None
        else:
            ctk.CTkLabel(main, text="⚠️ matplotlib non installé — graphique indisponible.\n"
                                     "Installez-le avec : pip install matplotlib",
                         text_color="orange").grid(row=2, column=0, pady=20)

    # ── Handlers ─────────────────────────────────────────────────────

    def _run_benchmark(self):
        self.run_btn.configure(state="disabled", text="⏳ Benchmark en cours...")
        self._set_status(self.bench_status, "Calcul AES (100 itérations) + RSA (5 itérations)...", "orange")
        self.update()
        thread = threading.Thread(target=self._benchmark_thread, daemon=True)
        thread.start()

    def _benchmark_thread(self):
        try:
            text = self.test_msg.get().strip() or "benchmark test"
            self._results = self.analyzer.full_comparison(text)
            self.after(0, self._on_benchmark_done)
        except Exception as e:
            self.after(0, lambda: self._set_status(self.bench_status, f"❌ {e}", "red"))
            self.after(0, lambda: self.run_btn.configure(state="normal", text="▶  Lancer le benchmark"))

    def _on_benchmark_done(self):
        r = self._results
        report = self.analyzer.format_report(r)
        self._set_textbox(self.result_box, report)
        self._set_status(
            self.bench_status,
            f"✅ Benchmark terminé — AES est ~{r['speedup_factor']}x plus rapide que RSA.",
            "green"
        )
        self.run_btn.configure(state="normal", text="▶  Lancer le benchmark")

        if MATPLOTLIB_AVAILABLE:
            self._draw_chart()

    def _draw_chart(self):
        """Draw a grouped bar chart comparing AES vs RSA timings."""
        r   = self._results
        aes = r["aes"]
        rsa = r["rsa"]

        # Remove old canvas
        if self._canvas:
            self._canvas.get_tk_widget().destroy()

        fig = Figure(figsize=(7, 3.2), dpi=96, facecolor="#1c1c1c")
        ax  = fig.add_subplot(111, facecolor="#1c1c1c")

        categories  = ["Génération\nde clé", "Chiffrement", "Déchiffrement", "TOTAL"]
        aes_values  = [aes["keygen_ms"], aes["encrypt_ms"], aes["decrypt_ms"], aes["total_ms"]]
        rsa_values  = [rsa["keygen_ms"], rsa["encrypt_ms"], rsa["decrypt_ms"], rsa["total_ms"]]

        x     = range(len(categories))
        width = 0.35

        bars_aes = ax.bar([i - width/2 for i in x], aes_values, width,
                          label="AES-256-CBC", color="#4fc3f7", alpha=0.9)
        bars_rsa = ax.bar([i + width/2 for i in x], rsa_values, width,
                          label="RSA-2048", color="#ef5350", alpha=0.9)

        # Labels on bars
        for bar in bars_aes:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                    f"{h:.3f}", ha="center", va="bottom", fontsize=8, color="white")
        for bar in bars_rsa:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                    f"{h:.1f}", ha="center", va="bottom", fontsize=8, color="white")

        ax.set_xticks(list(x))
        ax.set_xticklabels(categories, color="white", fontsize=10)
        ax.set_ylabel("Temps (ms)", color="white")
        ax.set_title(f"AES vs RSA — Facteur de vitesse : ×{r['speedup_factor']}",
                     color="white", fontsize=12, fontweight="bold")
        ax.tick_params(colors="white")
        ax.spines[:].set_color("#444")
        ax.legend(facecolor="#2a2a2a", labelcolor="white")
        fig.tight_layout()

        self._canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        self._canvas.draw()
        self._canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_textbox(widget, text):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _set_status(label, text, color):
        label.configure(text=text, text_color=color)
