# CryptoLab

A comprehensive Python application demonstrating modern cryptographic algorithms and their applications in ensuring confidentiality, integrity, and authentication.

## Features

- **Confidentiality**: AES-256-CBC symmetric encryption, RSA-2048 asymmetric encryption, and hybrid encryption schemes
- **Integrity**: SHA-256 hashing for data integrity verification
- **Authentication**: RSA-PSS digital signatures for non-repudiation
- **Certificates**: X.509 self-signed certificates
- **Performance**: Benchmarking of encryption algorithms
- **Interactive Simulations**: Educational attack simulations to understand cryptographic vulnerabilities

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
1. Clone or download the project:
   ```bash
   cd crypto-app
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage

Launch the application and navigate through the different cryptographic modules using the sidebar:

- **Confidentiality**: Encrypt/decrypt messages and files using AES, RSA, or hybrid methods
- **Integrity**: Compute and verify SHA-256 hashes
- **Signature**: Create and verify digital signatures
- **Certificate**: Generate and inspect X.509 certificates
- **Performance**: Run benchmarks comparing encryption speeds

Each module includes interactive simulations where you can play the role of an attacker to understand common cryptographic vulnerabilities.

## Project Structure

```
crypto-app/
├── main.py                    # Application entry point
├── requirements.txt           # Python dependencies
├── core/                      # Core cryptographic implementations
│   ├── symmetric.py           # AES-256-CBC encryption
│   ├── asymmetric.py          # RSA encryption and key management
│   ├── hashing.py             # SHA-256 hashing
│   ├── signature.py           # RSA-PSS digital signatures
│   ├── certificate.py         # X.509 certificate generation
│   └── performance.py         # Algorithm benchmarking
├── gui/                       # Graphical user interface
│   ├── main_window.py         # Main application window
│   ├── confidentiality_page.py # Confidentiality module UI
│   ├── integrity_page.py      # Integrity module UI
│   ├── signature_page.py      # Signature module UI
│   ├── certificate_page.py    # Certificate module UI
│   ├── performance_page.py    # Performance module UI
│   ├── theme.py               # UI theming
│   └── widgets.py             # Custom UI components
└── keys/                      # Generated cryptographic keys
```

## Key Management

The `keys/` directory stores cryptographic keys generated during runtime. To prevent this directory from being empty and ensure it's tracked by Git, create a `.gitkeep` file in the `keys/` folder:

```bash
touch keys/.gitkeep
```

This allows the directory structure to be maintained in version control while keeping sensitive key files out of the repository.

## Requirements

- cryptography: For cryptographic operations
- customtkinter: Modern GUI framework
- matplotlib: For performance charts

## Security Notes

This application is for educational purposes. In production environments:

- Use established cryptographic libraries
- Implement proper key management
- Follow security best practices
- Regularly update dependencies

## License

This project is provided for educational purposes.
