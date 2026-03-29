"""
Module: certificate.py
Class:  CertificateManager
Algo:   X.509 v3 self-signed certificate (RSA-2048 + SHA-256)
Libs:   cryptography
"""

import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """
    Generates, saves, loads, and inspects X.509 self-signed certificates.

    A digital certificate binds a public key to an identity.
    In a self-signed certificate, the issuer and subject are the same entity
    (no Certificate Authority is involved).

    CIA Target : Authentication (identity verification)
    Limit      : Self-signed certs are NOT trusted by browsers/OS by default.
                 A real PKI requires a trusted Certificate Authority (CA).
    """

    DEFAULT_VALIDITY_DAYS = 365

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate_self_signed_cert(self, subject_info: dict = None, validity_days: int = None):
        """
        Generate a self-signed X.509 v3 certificate with a fresh RSA-2048 key pair.

        Args:
            subject_info (dict): Optional subject fields:
                {
                    'common_name':    str  (CN)  — e.g. 'example.com'
                    'organization':   str  (O)   — e.g. 'ENSAF'
                    'country':        str  (C)   — 2-letter code, e.g. 'MA'
                    'state':          str  (ST)  — e.g. 'Fes-Meknes'
                    'locality':       str  (L)   — e.g. 'Fes'
                    'email':          str  (emailAddress)
                }
            validity_days (int): Certificate validity in days (default 365)

        Returns:
            tuple: (certificate, private_key)
        """
        info     = subject_info or {}
        validity = validity_days or self.DEFAULT_VALIDITY_DAYS

        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Build subject / issuer name
        name = self._build_name(info)

        # Build certificate
        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)                          # self-signed: issuer == subject
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        return cert, private_key

    # ------------------------------------------------------------------
    # Save / Load
    # ------------------------------------------------------------------

    def save_certificate(self, cert, path: str) -> None:
        """Save a certificate to a PEM file."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def save_private_key(self, private_key, path: str) -> None:
        """Save certificate private key to a PEM file (no password)."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def load_certificate(self, path: str):
        """
        Load a certificate from a PEM file.

        Raises:
            FileNotFoundError: If file does not exist
            ValueError       : If file is not a valid PEM certificate
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Certificate file not found: {path}")
        with open(path, "rb") as f:
            pem = f.read()
        try:
            return x509.load_pem_x509_certificate(pem, default_backend())
        except Exception:
            raise ValueError("Failed to load certificate — invalid PEM format.")

    # ------------------------------------------------------------------
    # Information extraction
    # ------------------------------------------------------------------

    def extract_info(self, cert) -> dict:
        """
        Extract human-readable information from a certificate.

        Args:
            cert: x509.Certificate object

        Returns:
            dict: All relevant certificate fields
        """
        def get_attr(name_obj, oid):
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                return "N/A"

        subject = cert.subject
        issuer  = cert.issuer

        return {
            "subject": {
                "common_name":  get_attr(subject, NameOID.COMMON_NAME),
                "organization": get_attr(subject, NameOID.ORGANIZATION_NAME),
                "country":      get_attr(subject, NameOID.COUNTRY_NAME),
                "state":        get_attr(subject, NameOID.STATE_OR_PROVINCE_NAME),
                "locality":     get_attr(subject, NameOID.LOCALITY_NAME),
            },
            "issuer": {
                "common_name":  get_attr(issuer, NameOID.COMMON_NAME),
                "organization": get_attr(issuer, NameOID.ORGANIZATION_NAME),
                "country":      get_attr(issuer, NameOID.COUNTRY_NAME),
            },
            "serial_number":  hex(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                                if hasattr(cert, "not_valid_before_utc")
                                else cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_valid_after":  cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                                if hasattr(cert, "not_valid_after_utc")
                                else cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
            "public_key_size": cert.public_key().key_size,
            "version":         str(cert.version),
            "self_signed":     cert.issuer == cert.subject,
        }

    def export_pem(self, cert) -> str:
        """Return the certificate as a PEM string."""
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def format_info_display(self, info: dict) -> str:
        """Format extracted certificate info as a readable string for GUI display."""
        lines = [
            "╔══════════════════════════════════════╗",
            "║       CERTIFICATE INFORMATION        ║",
            "╚══════════════════════════════════════╝",
            "",
            "── SUBJECT ──────────────────────────",
            f"  Common Name   : {info['subject']['common_name']}",
            f"  Organization  : {info['subject']['organization']}",
            f"  Country       : {info['subject']['country']}",
            f"  State         : {info['subject']['state']}",
            f"  Locality      : {info['subject']['locality']}",
            "",
            "── ISSUER ───────────────────────────",
            f"  Common Name   : {info['issuer']['common_name']}",
            f"  Organization  : {info['issuer']['organization']}",
            f"  Country       : {info['issuer']['country']}",
            "",
            "── VALIDITY ─────────────────────────",
            f"  Not Before    : {info['not_valid_before']}",
            f"  Not After     : {info['not_valid_after']}",
            "",
            "── TECHNICAL ────────────────────────",
            f"  Serial Number : {info['serial_number']}",
            f"  Key Size      : {info['public_key_size']} bits",
            f"  Version       : {info['version']}",
            f"  Self-Signed   : {info['self_signed']}",
            f"  Signature Alg : {info['signature_algorithm']}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_name(info: dict) -> x509.Name:
        """Build an X.509 Name object from a subject_info dict."""
        attributes = []

        cn = info.get("common_name", "localhost")
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))

        org = info.get("organization", "ENSAF")
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))

        country = info.get("country", "MA")
        if len(country) == 2:
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))

        state = info.get("state", "Fes-Meknes")
        if state:
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

        locality = info.get("locality", "Fes")
        if locality:
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

        return x509.Name(attributes)