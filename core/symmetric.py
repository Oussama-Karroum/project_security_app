"""
Module: symmetric.py
Class:  SymmetricCipher
Algo:   AES-256-CBC
Libs:   cryptography, os
Author: Project - OpenSSL to Python
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class SymmetricCipher:
    """
    Implements symmetric encryption and decryption using AES-256-CBC.

    AES (Advanced Encryption Standard) with a 256-bit key provides
    strong confidentiality. CBC (Cipher Block Chaining) mode ensures
    that identical plaintext blocks produce different ciphertext blocks.

    CIA Target : Confidentiality
    Limit      : Key must be shared securely (key distribution problem)
    """

    KEY_SIZE   = 32   # 256 bits
    BLOCK_SIZE = 16   # AES block = 128 bits
    IV_SIZE    = 16   # IV same as block size for CBC

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_key(self) -> bytes:
        """
        Generate a cryptographically secure random 256-bit AES key.

        Returns:
            bytes: 32-byte random key
        """
        return os.urandom(self.KEY_SIZE)

    def generate_iv(self) -> bytes:
        """
        Generate a random Initialisation Vector (IV).

        The IV must be unique for every encryption operation.
        It does NOT need to be secret — it is prepended to ciphertext.

        Returns:
            bytes: 16-byte random IV
        """
        return os.urandom(self.IV_SIZE)

    # ------------------------------------------------------------------
    # Text encryption / decryption
    # ------------------------------------------------------------------

    def encrypt_text(self, plaintext: str, key: bytes) -> bytes:
        """
        Encrypt a UTF-8 string using AES-256-CBC.

        The IV is randomly generated and prepended to the ciphertext
        so that it can be recovered during decryption.

        Args:
            plaintext (str): The message to encrypt
            key (bytes)    : 32-byte AES key

        Returns:
            bytes: IV (16 bytes) + ciphertext
        """
        self._validate_key(key)

        iv        = self.generate_iv()
        padded    = self._pad(plaintext.encode("utf-8"))
        cipher    = self._build_cipher(key, iv)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return iv + ciphertext          # IV prepended for later decryption

    def decrypt_text(self, data: bytes, key: bytes) -> str:
        """
        Decrypt AES-256-CBC ciphertext back to a UTF-8 string.

        Expects the first 16 bytes to be the IV (as produced by encrypt_text).

        Args:
            data (bytes): IV + ciphertext
            key (bytes) : 32-byte AES key

        Returns:
            str: Decrypted plaintext

        Raises:
            ValueError: If the key is wrong or data is corrupted
        """
        self._validate_key(key)

        iv         = data[:self.IV_SIZE]
        ciphertext = data[self.IV_SIZE:]
        cipher     = self._build_cipher(key, iv)
        decryptor  = cipher.decryptor()

        try:
            padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
            return self._unpad(padded_plain).decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed — wrong key or corrupted data.")

    # ------------------------------------------------------------------
    # File encryption / decryption
    # ------------------------------------------------------------------

    def encrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        """
        Encrypt a file using AES-256-CBC.

        Reads the source file, encrypts its content, and writes
        IV + ciphertext to the destination file.

        Args:
            input_path  (str)  : Path to the plaintext file
            output_path (str)  : Path where encrypted file will be written
            key         (bytes): 32-byte AES key

        Raises:
            FileNotFoundError: If input_path does not exist
            ValueError       : If the key size is invalid
        """
        self._validate_key(key)

        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        iv     = self.generate_iv()
        cipher = self._build_cipher(key, iv)
        encryptor = cipher.encryptor()

        with open(input_path, "rb") as f_in:
            raw = f_in.read()

        padded     = self._pad(raw)
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        with open(output_path, "wb") as f_out:
            f_out.write(iv + ciphertext)

    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        """
        Decrypt an AES-256-CBC encrypted file.

        Args:
            input_path  (str)  : Path to the encrypted file
            output_path (str)  : Path where decrypted file will be written
            key         (bytes): 32-byte AES key

        Raises:
            FileNotFoundError: If input_path does not exist
            ValueError       : If the key is wrong or file is corrupted
        """
        self._validate_key(key)

        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        with open(input_path, "rb") as f_in:
            data = f_in.read()

        iv         = data[:self.IV_SIZE]
        ciphertext = data[self.IV_SIZE:]
        cipher     = self._build_cipher(key, iv)
        decryptor  = cipher.decryptor()

        try:
            padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
            plain = self._unpad(padded_plain)
        except Exception:
            raise ValueError("File decryption failed — wrong key or corrupted file.")

        with open(output_path, "wb") as f_out:
            f_out.write(plain)

    # ------------------------------------------------------------------
    # Key serialisation helpers  (hex ↔ bytes)
    # ------------------------------------------------------------------

    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """Convert a key to a human-readable hex string."""
        return key.hex()

    @staticmethod
    def key_from_hex(hex_str: str) -> bytes:
        """
        Reconstruct a key from its hex representation.

        Raises:
            ValueError: If the hex string does not represent a valid 256-bit key
        """
        try:
            key = bytes.fromhex(hex_str.strip())
        except ValueError:
            raise ValueError("Invalid hex string for AES key.")
        if len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(
                f"Key must be {SymmetricCipher.KEY_SIZE} bytes "
                f"({SymmetricCipher.KEY_SIZE * 8} bits). Got {len(key)} bytes."
            )
        return key

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_cipher(self, key: bytes, iv: bytes) -> Cipher:
        """Build a Cipher object for AES-256-CBC."""
        return Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )

    def _pad(self, data: bytes) -> bytes:
        """Apply PKCS7 padding so data length is a multiple of BLOCK_SIZE."""
        padder = padding.PKCS7(self.BLOCK_SIZE * 8).padder()
        return padder.update(data) + padder.finalize()

    def _unpad(self, data: bytes) -> bytes:
        """Remove PKCS7 padding after decryption."""
        unpadder = padding.PKCS7(self.BLOCK_SIZE * 8).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """Raise ValueError if key is not exactly 32 bytes."""
        if not isinstance(key, bytes) or len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(
                f"AES key must be exactly {SymmetricCipher.KEY_SIZE} bytes. "
                f"Got: {len(key) if isinstance(key, bytes) else type(key)}"
            )
