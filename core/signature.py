"""
Module: signature.py
Class:  DigitalSignature
Algo:   RSA-PSS with SHA-256
Libs:   cryptography
"""

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    """
    Implements digital signature creation and verification using RSA-PSS.

    The signer uses their PRIVATE key to sign a message digest.
    Anyone with the corresponding PUBLIC key can verify the signature.

    This guarantees:
      - Authentication   : The message came from the private key holder
      - Non-repudiation  : The signer cannot deny having signed
      - Integrity        : The message was not altered after signing

    CIA Target : Authentication + Non-repudiation + Integrity
    Limit      : Key pair must be trustworthy (requires PKI / certificate)
    """

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign(self, message: bytes, private_key) -> bytes:
        """
        Sign a message with an RSA private key using PSS padding + SHA-256.

        The message is hashed internally by the signing algorithm.

        Args:
            message     (bytes): Data to sign (any length)
            private_key        : RSA private key object

        Returns:
            bytes: Digital signature (same length as RSA key size)
        """
        signature = private_key.sign(
            message,
            self._pss_padding(),
            hashes.SHA256()
        )
        return signature

    def sign_text(self, text: str, private_key) -> bytes:
        """
        Convenience method: sign a UTF-8 string.

        Args:
            text        (str): Message to sign
            private_key      : RSA private key object

        Returns:
            bytes: Digital signature
        """
        return self.sign(text.encode("utf-8"), private_key)

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        """
        Verify a digital signature with an RSA public key.

        Args:
            message    (bytes): Original message
            signature  (bytes): Signature to verify
            public_key        : RSA public key object

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                message,
                self._pss_padding(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def verify_text(self, text: str, signature: bytes, public_key) -> bool:
        """
        Convenience method: verify signature of a UTF-8 string.

        Args:
            text       (str)  : Original message
            signature  (bytes): Signature to verify
            public_key        : RSA public key object

        Returns:
            bool: True if valid, False if tampered or wrong key
        """
        return self.verify(text.encode("utf-8"), signature, public_key)

    # ------------------------------------------------------------------
    # Signature serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def signature_to_hex(signature: bytes) -> str:
        """Convert signature bytes to a hex string for display."""
        return signature.hex()

    @staticmethod
    def signature_from_hex(hex_str: str) -> bytes:
        """
        Reconstruct signature bytes from hex string.

        Raises:
            ValueError: If the hex string is invalid
        """
        try:
            return bytes.fromhex(hex_str.strip())
        except ValueError:
            raise ValueError("Invalid hex string for signature.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pss_padding():
        """
        Return PSS padding configuration.

        PSS (Probabilistic Signature Scheme) is the recommended padding
        for RSA signatures — more secure than the older PKCS1v15.
        """
        return asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        )
