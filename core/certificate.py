import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """X.509 v3 self-signed certificates (RSA-2048 + SHA-256). CIA: Authentication."""

    DEFAULT_VALIDITY_DAYS = 365

    def generate_self_signed_cert(self, subject_info: dict = None, validity_days: int = None):
        """Returns (certificate, private_key)."""
        info     = subject_info or {}
        validity = validity_days or self.DEFAULT_VALIDITY_DAYS
        priv     = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        name = self._build_name(info)
        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
            .sign(priv, hashes.SHA256(), default_backend())
        )
        return cert, priv

    def save_certificate(self, cert, path: str) -> None:
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def save_private_key(self, private_key, path: str) -> None:
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def load_certificate(self, path: str):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Certificate file not found: {path}")
        with open(path, "rb") as f:
            pem = f.read()
        try:
            return x509.load_pem_x509_certificate(pem, default_backend())
        except Exception:
            raise ValueError("Failed to load certificate — invalid PEM format.")

    def extract_info(self, cert) -> dict:
        def get_attr(name_obj, oid):
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                return "N/A"

        s, i = cert.subject, cert.issuer

        def fmt_date(dt_attr):
            try:
                return getattr(cert, dt_attr + "_utc").strftime("%Y-%m-%d %H:%M:%S UTC")
            except AttributeError:
                return getattr(cert, dt_attr).strftime("%Y-%m-%d %H:%M:%S UTC")

        return {
            "subject": {
                "common_name":  get_attr(s, NameOID.COMMON_NAME),
                "organization": get_attr(s, NameOID.ORGANIZATION_NAME),
                "country":      get_attr(s, NameOID.COUNTRY_NAME),
                "state":        get_attr(s, NameOID.STATE_OR_PROVINCE_NAME),
                "locality":     get_attr(s, NameOID.LOCALITY_NAME),
            },
            "issuer": {
                "common_name":  get_attr(i, NameOID.COMMON_NAME),
                "organization": get_attr(i, NameOID.ORGANIZATION_NAME),
                "country":      get_attr(i, NameOID.COUNTRY_NAME),
            },
            "serial_number":        hex(cert.serial_number),
            "not_valid_before":     fmt_date("not_valid_before"),
            "not_valid_after":      fmt_date("not_valid_after"),
            "signature_algorithm":  cert.signature_algorithm_oid.dotted_string,
            "public_key_size":      cert.public_key().key_size,
            "version":              str(cert.version),
            "self_signed":          cert.issuer == cert.subject,
        }

    def export_pem(self, cert) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def format_info_display(self, info: dict) -> str:
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

    @staticmethod
    def _build_name(info: dict) -> x509.Name:
        attrs = [
            x509.NameAttribute(NameOID.COMMON_NAME,          info.get("common_name",  "localhost")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,    info.get("organization", "ENSAF")),
        ]
        country = info.get("country", "MA")
        if len(country) == 2:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
        state = info.get("state", "Fes-Meknes")
        if state:
            attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        locality = info.get("locality", "Fes")
        if locality:
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        return x509.Name(attrs)
