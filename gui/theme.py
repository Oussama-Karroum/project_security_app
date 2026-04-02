# ───────────────────────── DARK MODE ──────────────────────────────────
DARK = {
    # backgrounds
    "BG_DEEP":   "#0a0e14",
    "BG_CARD":   "#111820",
    "BG_INPUT":  "#0d1117",
    "BG_HOVER":  "#1a2332",
    "BORDER":    "#1e2d3d",

    # accents
    "CYAN":      "#00d4ff",
    "GREEN":     "#2ecc71",
    "AMBER":     "#f39c12",
    "RED":       "#e74c3c",
    "PURPLE":    "#9b59b6",
    "BLUE":      "#3498db",
    "TEAL":      "#1abc9c",

    # text
    "TEXT_BRIGHT": "#e8f4fd",
    "TEXT_DIM":    "#5a7a9a",
    "TEXT_CODE":   "#a8d8a8",

    # pre-computed solid tints  (blended on BG_DEEP=#0a0e14)
    "CYAN_BG":      "#09212b",
    "CYAN_HOVER":   "#073947",
    "CYAN_BORDER":  "#073f4e",

    "GREEN_BG":     "#0d2318",
    "GREEN_HOVER":  "#113d23",
    "GREEN_BORDER": "#134a26",

    "AMBER_BG":     "#1f1a0f",
    "AMBER_HOVER":  "#372e12",
    "AMBER_BORDER": "#3e3312",

    "RED_BG":       "#1f0f0f",
    "RED_HOVER":    "#3a1212",
    "RED_BORDER":   "#441414",

    "PURPLE_BG":    "#17111f",
    "PURPLE_HOVER": "#281d38",
    "PURPLE_BORDER":"#2e2040",

    "BLUE_BG":      "#0e1820",
    "BLUE_HOVER":   "#152638",
    "BLUE_BORDER":  "#182c42",

    "TEAL_BG":      "#0a1f1c",
    "TEAL_HOVER":   "#0d342f",
    "TEAL_BORDER":  "#0f3a34",

    # canvas solid tints (used in tk.Canvas fill/outline)
    "C_CYAN_FILL":    "#09212b",
    "C_CYAN_OUTLINE": "#073f4e",
    "C_BLUE_FILL":    "#0e1820",
    "C_BLUE_OUTLINE": "#182c42",
    "C_PURPLE_FILL":  "#17111f",
    "C_PURPLE_OUTLINE":"#2e2040",
    "C_GREEN_FILL":   "#0d2318",
    "C_GREEN_OUTLINE":"#134a26",
    "C_AMBER_FILL":   "#1f1a0f",
    "C_RED_FILL":     "#1f0f0f",
    "C_RED_OUTLINE":  "#441414",
    "C_TEAL_FILL":    "#0a1f1c",
    "C_TEAL_OUTLINE": "#0f3a34",
    "RED_MED":        "#5c1a1a",
}

# ───────────────────────── LIGHT MODE ─────────────────────────────────
LIGHT = {
    # backgrounds — warm paper whites
    "BG_DEEP":   "#f4f6f9",
    "BG_CARD":   "#ffffff",
    "BG_INPUT":  "#f9fafc",
    "BG_HOVER":  "#e8eef5",
    "BORDER":    "#d0d9e6",

    # accents — muted, professional
    "CYAN":      "#0077aa",
    "GREEN":     "#1a7a3c",
    "AMBER":     "#b35c00",
    "RED":       "#c0392b",
    "PURPLE":    "#6c3483",
    "BLUE":      "#1a5276",
    "TEAL":      "#117a65",

    # text
    "TEXT_BRIGHT": "#1a2332",
    "TEXT_DIM":    "#5d7285",
    "TEXT_CODE":   "#2e4a2e",

    # pre-computed solid tints  (blended on BG_DEEP=#f4f6f9)
    "CYAN_BG":      "#ddeef5",
    "CYAN_HOVER":   "#cce4f0",
    "CYAN_BORDER":  "#aacfe8",

    "GREEN_BG":     "#ddf0e6",
    "GREEN_HOVER":  "#cce8d9",
    "GREEN_BORDER": "#aad4bf",

    "AMBER_BG":     "#f5ead5",
    "AMBER_HOVER":  "#edddb5",
    "AMBER_BORDER": "#d9c080",

    "RED_BG":       "#f5dada",
    "RED_HOVER":    "#ecc5c5",
    "RED_BORDER":   "#d99090",

    "PURPLE_BG":    "#e8ddf5",
    "PURPLE_HOVER": "#daccee",
    "PURPLE_BORDER":"#c0a0d9",

    "BLUE_BG":      "#d9e8f5",
    "BLUE_HOVER":   "#c8dcee",
    "BLUE_BORDER":  "#a0c4e0",

    "TEAL_BG":      "#d5f0ec",
    "TEAL_HOVER":   "#c0e8e2",
    "TEAL_BORDER":  "#90d0c8",

    # canvas tints
    "C_CYAN_FILL":    "#ddeef5",
    "C_CYAN_OUTLINE": "#aacfe8",
    "C_BLUE_FILL":    "#d9e8f5",
    "C_BLUE_OUTLINE": "#a0c4e0",
    "C_PURPLE_FILL":  "#e8ddf5",
    "C_PURPLE_OUTLINE":"#c0a0d9",
    "C_GREEN_FILL":   "#ddf0e6",
    "C_GREEN_OUTLINE":"#aad4bf",
    "C_AMBER_FILL":   "#f5ead5",
    "C_RED_FILL":     "#f5dada",
    "C_RED_OUTLINE":  "#d99090",
    "C_TEAL_FILL":    "#d5f0ec",
    "C_TEAL_OUTLINE": "#90d0c8",
    "RED_MED":        "#e8a0a0",
}

# ──────────────────── Active palette (mutable) ─────────────────────────
# Pages import from here. Call set_mode("dark"/"light") to switch.
_current = dict(DARK)

def set_mode(mode: str):
    """Switch palette. Call this before redrawing pages."""
    global _current
    _current.clear()
    _current.update(DARK if mode == "dark" else LIGHT)

def get(key: str) -> str:
    return _current.get(key, "#ff00ff")  # magenta = missing key


# ──────────────── Convenience module-level names ───────────────────────
# These are READ at import time — pages must call get() or re-import
# if they want live switching. But since we rebuild pages on mode change
# in MainApp, a simple module-level snapshot is sufficient.

def _export():
    """Re-export all keys as module globals."""
    import sys
    m = sys.modules[__name__]
    for k, v in _current.items():
        setattr(m, k, v)

_export()

# CIA model
CIA        = {"C": None, "I": None, "A": None}
CIA_LABELS = {"C": "Confidentialite", "I": "Integrite", "A": "Authenticite"}

def _update_cia():
    CIA["C"] = _current["BLUE"]
    CIA["I"] = _current["TEAL"]
    CIA["A"] = _current["PURPLE"]

_update_cia()

# Fonts
FONT_MONO = "Courier"
RADIUS    = 8

# ──────────────────────── Tooltips ────────────────────────────────────
TOOLTIPS = {
    "IV": (
        "Vecteur d'Initialisation (IV)\n\n"
        "Valeur aleatoire de 16 octets ajoutee avant le premier bloc AES.\n"
        "Garantit que deux chiffrements du meme texte avec la meme cle\n"
        "produisent des ciphertexts differents.\n\n"
        "L'IV n'est PAS secret - il est transmis avec le ciphertext.\n"
        "Ce qui est secret, c'est uniquement la cle."
    ),
    "padding": (
        "Rembourrage PKCS7\n\n"
        "AES opere sur des blocs de 128 bits exactement.\n"
        "PKCS7 complete le dernier bloc avec des octets de valeur N\n"
        "ou N = nombre d'octets manquants.\n\n"
        "Exemple : 3 octets manquants => on ajoute 03 03 03"
    ),
    "OAEP": (
        "OAEP - Optimal Asymmetric Encryption Padding\n\n"
        "Schema de padding pour RSA qui introduit de l'aleatoire.\n"
        "Empeche les attaques par texte choisi (CCA2).\n"
        "Utilise SHA-256 comme fonction de hachage interne.\n\n"
        "Standard recommande : RSA-OAEP (PKCS#1 v2.1)"
    ),
    "PSS": (
        "PSS - Probabilistic Signature Scheme\n\n"
        "Padding de signature RSA avec sel aleatoire.\n"
        "Plus sur que l'ancien PKCS1v15 car les signatures sont\n"
        "non-deterministes (deux signatures du meme message different).\n\n"
        "Prouvablement securise dans le modele de l'oracle aleatoire."
    ),
    "salt": (
        "Sel (Salt)\n\n"
        "Valeur aleatoire ajoutee avant de hacher un mot de passe.\n"
        "Empeche les attaques par table arc-en-ciel (rainbow table).\n"
        "Rend unique chaque hash meme pour des mots de passe identiques.\n\n"
        "Utilise dans : bcrypt, PBKDF2, Argon2"
    ),
    "signature": (
        "Signature Numerique\n\n"
        "La cle PRIVEE signe - la cle PUBLIQUE verifie.\n\n"
        "Garanties :\n"
        "  Authentification  : le message vient du detenteur de la cle privee\n"
        "  Non-repudiation   : le signataire ne peut pas nier\n"
        "  Integrite         : toute modification invalide la signature\n\n"
        "Algorithme : RSA-PSS avec SHA-256"
    ),
    "SHA-256": (
        "SHA-256 - Secure Hash Algorithm 256 bits\n\n"
        "Famille : SHA-2 (NIST, 2001)\n"
        "Sortie  : 256 bits = 32 octets = 64 caracteres hexadecimaux\n\n"
        "Proprietes :\n"
        "  Resistance a la pre-image  : impossible de retrouver x depuis H(x)\n"
        "  Resistance aux collisions  : impossible de trouver x!=y, H(x)=H(y)\n"
        "  Effet avalanche            : 1 bit modifie => ~50% des bits changent"
    ),
    "AES": (
        "AES - Advanced Encryption Standard\n\n"
        "Selectionne par le NIST en 2001 (algorithme Rijndael).\n"
        "Chiffrement par blocs de 128 bits, cles de 128/192/256 bits.\n\n"
        "Mode CBC (Cipher Block Chaining) :\n"
        "Chaque bloc est XORe avec le ciphertext du bloc precedent\n"
        "avant chiffrement - les blocs identiques donnent des ciphertexts differents."
    ),
    "RSA": (
        "RSA - Rivest-Shamir-Adleman (1977)\n\n"
        "Base sur la difficulte de factoriser de grands entiers.\n"
        "Cle publique  : (n, e) - pour chiffrer\n"
        "Cle privee    : (n, d) - pour dechiffrer\n\n"
        "Taille recommandee : 2048 bits minimum\n"
        "Limite : lent, donnees max ~190 octets pour 2048 bits."
    ),
    "hybride": (
        "Chiffrement Hybride\n\n"
        "Combine AES (vitesse) + RSA (echange de cle securise).\n\n"
        "Etapes :\n"
        "  1. Generer une cle AES aleatoire (session key)\n"
        "  2. Chiffrer les donnees avec AES\n"
        "  3. Chiffrer la cle AES avec RSA (cle publique du destinataire)\n"
        "  4. Transmettre : ciphertext AES + cle AES chiffree RSA\n\n"
        "Utilise dans : TLS, PGP, SSH"
    ),
    "certificat": (
        "Certificat X.509\n\n"
        "Lie une cle publique a une identite, signe par une CA.\n\n"
        "Champs principaux :\n"
        "  Subject (CN, O, C)   - identite du titulaire\n"
        "  Issuer               - autorite de certification\n"
        "  Validity             - dates de debut et fin\n"
        "  Public Key           - cle publique du titulaire\n"
        "  Serial Number        - identifiant unique\n"
        "  Signature CA         - preuve d'authenticite\n\n"
        "Auto-signe : issuer == subject (pas de CA tierce)"
    ),
    "CIA": (
        "Modele CIA\n\n"
        "Les trois piliers de la securite informatique :\n\n"
        "  C - Confidentialite\n"
        "      Seuls les destinataires autorises lisent les donnees.\n"
        "      Outils : AES, RSA, chiffrement hybride.\n\n"
        "  I - Integrite\n"
        "      Les donnees n'ont pas ete modifiees.\n"
        "      Outils : SHA-256, HMAC, signature numerique.\n\n"
        "  A - Authenticite (Availability en CIA classique)\n"
        "      L'emetteur est bien qui il pretend etre.\n"
        "      Outils : signature RSA-PSS, certificat X.509."
    ),
}
