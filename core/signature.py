from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    """RSA-PSS digital signatures. CIA: Authentication + Non-repudiation + Integrity."""

    def sign(self, message: bytes, private_key) -> bytes:
        return private_key.sign(message, self._pss(), hashes.SHA256())

    def sign_text(self, text: str, private_key) -> bytes:
        return self.sign(text.encode("utf-8"), private_key)

    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(signature, message, self._pss(), hashes.SHA256())
            return True
        except (InvalidSignature, Exception):
            return False

    def verify_text(self, text: str, signature: bytes, public_key) -> bool:
        return self.verify(text.encode("utf-8"), signature, public_key)

    @staticmethod
    def signature_to_hex(signature: bytes) -> str:
        return signature.hex()

    @staticmethod
    def signature_from_hex(hex_str: str) -> bytes:
        try:
            return bytes.fromhex(hex_str.strip())
        except ValueError:
            raise ValueError("Invalid hex string for signature.")

    @staticmethod
    def _pss():
        return asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        )
