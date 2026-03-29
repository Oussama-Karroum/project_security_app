"""
Module: asymmetric.py
Class:  AsymmetricCipher
Algo:   RSA-2048/4096 with OAEP + Hybrid encryption
Libs:   cryptography, os
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from core.symmetric import SymmetricCipher


class AsymmetricCipher:
    """
    Implements RSA asymmetric encryption/decryption and hybrid encryption.

    RSA uses a key pair: public key to encrypt, private key to decrypt.
    Hybrid encryption combines RSA + AES: AES encrypts the data,
    RSA encrypts the AES key — best of both worlds.

    CIA Target : Confidentiality
    Limit      : RSA is slow for large data; max ~190 bytes for 2048-bit key
    """

    # ------------------------------------------------------------------
    # Key pair generation
    # ------------------------------------------------------------------

    def generate_key_pair(self, key_size: int = 2048):
        """
        Generate an RSA key pair.

        Args:
            key_size (int): 2048 or 4096 bits (default 2048)

        Returns:
            tuple: (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    # ------------------------------------------------------------------
    # RSA encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes, public_key) -> bytes:
        """
        Encrypt data with RSA-OAEP (SHA-256).

        Args:
            plaintext  (bytes): Data to encrypt (max ~190 bytes for 2048-bit key)
            public_key       : RSA public key object

        Returns:
            bytes: RSA ciphertext
        """
        return public_key.encrypt(plaintext, self._oaep_padding())

    def decrypt(self, ciphertext: bytes, private_key) -> bytes:
        """
        Decrypt RSA-OAEP ciphertext.

        Args:
            ciphertext  (bytes): Encrypted data
            private_key        : RSA private key object

        Returns:
            bytes: Original plaintext

        Raises:
            ValueError: If decryption fails (wrong key or corrupt data)
        """
        try:
            return private_key.decrypt(ciphertext, self._oaep_padding())
        except Exception:
            raise ValueError("RSA decryption failed — wrong private key or corrupted data.")

    # ------------------------------------------------------------------
    # Hybrid encryption  (RSA + AES)
    # ------------------------------------------------------------------

    def hybrid_encrypt(self, plaintext: str, public_key) -> dict:
        """
        Encrypt data using hybrid scheme: AES for data, RSA for AES key.

        Steps:
          1. Generate a random AES-256 key
          2. Encrypt the plaintext with AES-CBC
          3. Encrypt the AES key with RSA-OAEP
          4. Return both encrypted blobs

        Args:
            plaintext  (str): Message to encrypt
            public_key      : RSA public key

        Returns:
            dict: {
                'encrypted_aes_key': bytes,
                'ciphertext':        bytes,
            }
        """
        sym = SymmetricCipher()
        aes_key        = sym.generate_key()
        ciphertext     = sym.encrypt_text(plaintext, aes_key)
        enc_aes_key    = self.encrypt(aes_key, public_key)

        return {
            "encrypted_aes_key": enc_aes_key,
            "ciphertext":        ciphertext,
        }

    def hybrid_decrypt(self, encrypted_aes_key: bytes, ciphertext: bytes, private_key) -> str:
        """
        Decrypt a hybrid-encrypted message.

        Steps:
          1. Decrypt the AES key with RSA private key
          2. Decrypt the ciphertext with the recovered AES key

        Args:
            encrypted_aes_key (bytes): RSA-encrypted AES key
            ciphertext        (bytes): AES-encrypted data
            private_key             : RSA private key

        Returns:
            str: Original plaintext

        Raises:
            ValueError: If RSA or AES decryption fails
        """
        sym     = SymmetricCipher()
        aes_key = self.decrypt(encrypted_aes_key, private_key)
        return sym.decrypt_text(ciphertext, aes_key)

    # ------------------------------------------------------------------
    # Key serialisation
    # ------------------------------------------------------------------

    def private_key_to_pem(self, private_key, password: bytes = None) -> bytes:
        """Serialize private key to PEM format (optionally password-protected)."""
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        )

    def public_key_to_pem(self, public_key) -> bytes:
        """Serialize public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_key_from_pem(self, pem: bytes, password: bytes = None):
        """Load a private key from PEM bytes."""
        try:
            return serialization.load_pem_private_key(pem, password=password, backend=default_backend())
        except Exception:
            raise ValueError("Failed to load private key — invalid PEM or wrong password.")

    def public_key_from_pem(self, pem: bytes):
        """Load a public key from PEM bytes."""
        try:
            return serialization.load_pem_public_key(pem, backend=default_backend())
        except Exception:
            raise ValueError("Failed to load public key — invalid PEM data.")

    def save_keys(self, private_key, public_key, directory: str = "keys") -> tuple:
        """Save PEM key pair to disk. Returns (private_path, public_path)."""
        os.makedirs(directory, exist_ok=True)
        priv_path = os.path.join(directory, "private_key.pem")
        pub_path  = os.path.join(directory, "public_key.pem")
        with open(priv_path, "wb") as f:
            f.write(self.private_key_to_pem(private_key))
        with open(pub_path, "wb") as f:
            f.write(self.public_key_to_pem(public_key))
        return priv_path, pub_path

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _oaep_padding():
        """Return OAEP padding with SHA-256 (recommended for RSA encryption)."""
        return asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )