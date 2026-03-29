# 🔐 CryptoApp — ENSAF | Prof. Said Hraoui
**Projet de TP — Application de Cryptographie en Python**
De OpenSSL à une application Python moderne

---

## ⚙️ Installation (WSL / Linux / macOS)

```bash
# 1. Cloner / copier le projet
cd project_security_app

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application
python main.py
```

## 📁 Structure
```
project_security_app/
├── main.py                  # Point d'entrée
├── requirements.txt
├── core/                    # Logique cryptographique pure
│   ├── symmetric.py         # AES-256-CBC
│   ├── asymmetric.py        # RSA-2048 + Hybride
│   ├── hashing.py           # SHA-256
│   ├── signature.py         # RSA-PSS
│   ├── certificate.py       # X.509 auto-signé
│   └── performance.py       # Benchmark AES vs RSA
├── gui/                     # Interface CustomTkinter
│   ├── main_window.py       # Fenêtre principale + navigation
│   ├── confidentiality_page.py
│   ├── integrity_page.py
│   ├── signature_page.py
│   ├── certificate_page.py
│   └── performance_page.py
└── keys/                    # Clés générées à l'exécution
```

## 🔬 Modules cryptographiques
| Module | Algorithme | CIA |
|--------|-----------|-----|
| AES | AES-256-CBC | Confidentialité |
| RSA | RSA-2048 OAEP | Confidentialité |
| Hybride | RSA + AES | Confidentialité |
| Hash | SHA-256 | Intégrité |
| Signature | RSA-PSS SHA-256 | Auth + Non-répudiation |
| Certificat | X.509 v3 | Authentification |
