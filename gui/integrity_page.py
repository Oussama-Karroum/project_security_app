"""
Module: integrity_page.py
Role:   GUI page for SHA-256 hashing, integrity verification, tampering demo
        Calls core.hashing — zero crypto code here
"""

import customtkinter as ctk
from tkinter import filedialog
from core.hashing import HashManager


class IntegrityPage(ctk.CTkFrame):
    """
    Integrity page — SHA-256, verification, avalanche effect demonstration.

    CIA Objective : Integrity
    """

    INFO_TEXT = (
        "🔗  INTÉGRITÉ\n\n"
        "Objectif CIA : Garantir que les données n'ont pas été altérées en transit ou au repos.\n\n"
        "• SHA-256 produit un condensé de 256 bits (64 caractères hex).\n"
        "• Toute modification — même d'un seul bit — produit un condensé totalement différent\n"
        "  (effet avalanche).\n\n"
        "• Limite : Le hachage seul ne prouve pas l'origine (pas d'authentification).\n"
        "  Pour l'authentification, on combine hash + signature numérique (HMAC, DSA)."
    )

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.hm = HashManager()
        self._reference_hash = None

        self._build_info_banner()
        self._build_tabs()

    def _build_info_banner(self):
        banner = ctk.CTkTextbox(self, height=130, wrap="word", font=ctk.CTkFont(size=12))
        banner.insert("0.0", self.INFO_TEXT)
        banner.configure(state="disabled")
        banner.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.tabs.add("🔢  Calculer condensé")
        self.tabs.add("✅  Vérifier intégrité")
        self.tabs.add("💥  Simulation altération")

        self._build_hash_tab(self.tabs.tab("🔢  Calculer condensé"))
        self._build_verify_tab(self.tabs.tab("✅  Vérifier intégrité"))
        self._build_tamper_tab(self.tabs.tab("💥  Simulation altération"))

    # ── Hash tab ─────────────────────────────────────────────────────

    def _build_hash_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(parent, text="Texte ou fichier à hacher :").grid(
            row=0, column=0, padx=8, pady=(8,0), sticky="w")
        self.hash_input = ctk.CTkTextbox(parent, height=100)
        self.hash_input.grid(row=1, column=0, padx=8, pady=4, sticky="ew")

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=8, pady=4, sticky="ew")
        ctk.CTkButton(btn_frame, text="# Calculer SHA-256 (texte)", command=self._hash_text).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="📂 Hacher un fichier", command=self._hash_file).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="📌 Mémoriser ce hash", command=self._save_reference).pack(side="left", padx=4)

        ctk.CTkLabel(parent, text="Condensé SHA-256 :").grid(row=3, column=0, padx=8, pady=(12,0), sticky="w")
        self.hash_output = ctk.CTkEntry(parent, font=ctk.CTkFont(family="Courier", size=12))
        self.hash_output.grid(row=4, column=0, padx=8, pady=4, sticky="ew")

        self.hash_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=12))
        self.hash_status.grid(row=5, column=0, padx=8, pady=4, sticky="w")

    # ── Verify tab ───────────────────────────────────────────────────

    def _build_verify_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(parent, text="Texte à vérifier :").grid(row=0, column=0, padx=8, pady=(8,0), sticky="w")
        self.verify_input = ctk.CTkTextbox(parent, height=90)
        self.verify_input.grid(row=1, column=0, padx=8, pady=4, sticky="ew")

        ref_frame = ctk.CTkFrame(parent)
        ref_frame.grid(row=2, column=0, padx=8, pady=8, sticky="ew")
        ref_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ref_frame, text="Hash de référence :", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=10, pady=8, sticky="w")
        self.verify_ref_entry = ctk.CTkEntry(
            ref_frame, placeholder_text="Collez le hash SHA-256 attendu (ou utilisez 'Mémoriser')",
            font=ctk.CTkFont(family="Courier", size=11))
        self.verify_ref_entry.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(ref_frame, text="Utiliser mémorisé", width=140,
                      command=self._use_saved_ref).grid(row=0, column=2, padx=8, pady=8)

        ctk.CTkButton(parent, text="✅ Vérifier intégrité", command=self._verify_integrity).grid(
            row=3, column=0, padx=8, pady=8, sticky="w")

        self.verify_result = ctk.CTkTextbox(parent, height=90)
        self.verify_result.grid(row=4, column=0, padx=8, pady=4, sticky="ew")

        self.verify_status = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=13, weight="bold"))
        self.verify_status.grid(row=5, column=0, padx=8, pady=4, sticky="w")

    # ── Tamper simulation tab ─────────────────────────────────────────

    def _build_tamper_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        desc = ctk.CTkLabel(
            parent,
            text="Démonstration de l'effet avalanche : une modification minime → condensé totalement différent.",
            font=ctk.CTkFont(size=12), text_color="gray", wraplength=640
        )
        desc.grid(row=0, column=0, columnspan=2, padx=8, pady=8, sticky="w")

        ctk.CTkLabel(parent, text="Message original :").grid(row=1, column=0, padx=8, pady=(4,0), sticky="w")
        self.tamper_input = ctk.CTkTextbox(parent, height=70)
        self.tamper_input.grid(row=2, column=0, padx=8, pady=4, sticky="ew")
        self.tamper_input.insert("0.0", "Bonjour, ceci est un message de test.")

        ctk.CTkLabel(parent, text="Message altéré (généré automatiquement) :").grid(
            row=1, column=1, padx=8, pady=(4,0), sticky="w")
        self.tamper_modified = ctk.CTkTextbox(parent, height=70)
        self.tamper_modified.grid(row=2, column=1, padx=8, pady=4, sticky="ew")

        ctk.CTkButton(parent, text="💥 Simuler altération et comparer", command=self._simulate_tamper).grid(
            row=3, column=0, columnspan=2, padx=8, pady=8, sticky="w")

        self.tamper_result = ctk.CTkTextbox(parent, height=130, font=ctk.CTkFont(family="Courier", size=11))
        self.tamper_result.grid(row=4, column=0, columnspan=2, padx=8, pady=4, sticky="ew")

    # ── Handlers ─────────────────────────────────────────────────────

    def _hash_text(self):
        try:
            text = self.hash_input.get("0.0", "end").strip()
            if not text:
                raise ValueError("Veuillez entrer un texte.")
            digest = self.hm.hash_text(text)
            self._set_entry(self.hash_output, digest)
            self._set_status(self.hash_status, "✅ SHA-256 calculé.", "green")
        except Exception as e:
            self._set_status(self.hash_status, f"❌ {e}", "red")

    def _hash_file(self):
        try:
            path = filedialog.askopenfilename(title="Choisir un fichier")
            if not path:
                return
            digest = self.hm.hash_file(path)
            self._set_entry(self.hash_output, digest)
            self._set_status(self.hash_status, f"✅ Hash du fichier calculé.", "green")
        except Exception as e:
            self._set_status(self.hash_status, f"❌ {e}", "red")

    def _save_reference(self):
        val = self.hash_output.get().strip()
        if not val:
            self._set_status(self.hash_status, "❌ Calculez d'abord un hash.", "red")
            return
        self._reference_hash = val
        self._set_status(self.hash_status, "📌 Hash mémorisé comme référence.", "blue")

    def _use_saved_ref(self):
        if not self._reference_hash:
            return
        self._set_entry(self.verify_ref_entry, self._reference_hash)

    def _verify_integrity(self):
        try:
            text = self.verify_input.get("0.0", "end").strip()
            ref  = self.verify_ref_entry.get().strip()
            if not text or not ref:
                raise ValueError("Texte et hash de référence requis.")
            computed = self.hm.hash_text(text)
            match    = self.hm.verify_text_integrity(text, ref)
            result   = (
                f"Hash calculé  : {computed}\n"
                f"Hash référence: {ref}\n"
                f"Résultat      : {'✅ INTÉGRITÉ CONFIRMÉE' if match else '❌ ALTÉRATION DÉTECTÉE'}"
            )
            self._set_textbox(self.verify_result, result)
            color = "green" if match else "red"
            msg   = "✅ Intégrité confirmée — données non altérées." if match else "❌ Altération détectée — données compromises!"
            self._set_status(self.verify_status, msg, color)
        except Exception as e:
            self._set_status(self.verify_status, f"❌ {e}", "red")

    def _simulate_tamper(self):
        try:
            original = self.tamper_input.get("0.0", "end").strip()
            if not original:
                raise ValueError("Entrez un message original.")
            modified = self.hm.simulate_tampering(original)
            self._set_textbox(self.tamper_modified, modified)
            cmp = self.hm.compare_hashes(original, modified)
            result = (
                f"Original  : {original}\n"
                f"Altéré    : {modified}\n\n"
                f"Hash original : {cmp['original_hash']}\n"
                f"Hash altéré   : {cmp['modified_hash']}\n\n"
                f"Correspondance    : {cmp['match']}\n"
                f"Caractères hex différents : {cmp['diff_chars']} / 64\n\n"
                f"→ Effet avalanche : {cmp['diff_chars']/64*100:.1f}% du condensé a changé !"
            )
            self._set_textbox(self.tamper_result, result)
        except Exception as e:
            self._set_textbox(self.tamper_result, f"❌ {e}")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_entry(widget, text):
        widget.configure(state="normal")
        widget.delete(0, "end")
        widget.insert(0, text)

    @staticmethod
    def _set_textbox(widget, text):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)

    @staticmethod
    def _set_status(label, text, color):
        label.configure(text=text, text_color=color)
