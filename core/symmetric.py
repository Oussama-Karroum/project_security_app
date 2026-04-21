import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class SymmetricCipher:
    """AES-256-CBC symmetric encryption. CIA: Confidentiality."""

    KEY_SIZE   = 32
    BLOCK_SIZE = 16
    IV_SIZE    = 16

    def generate_key(self) -> bytes:
        return os.urandom(self.KEY_SIZE)

    def generate_iv(self) -> bytes:
        return os.urandom(self.IV_SIZE)

    def encrypt_text(self, plaintext: str, key: bytes) -> bytes:
        """Returns IV (16 bytes) + ciphertext."""
        self._validate_key(key)
        iv        = self.generate_iv()
        padded    = self._pad(plaintext.encode("utf-8"))
        encryptor = self._build_cipher(key, iv).encryptor()
        return iv + encryptor.update(padded) + encryptor.finalize()

    def decrypt_text(self, data: bytes, key: bytes) -> str:
        """Expects IV (16 bytes) prepended to ciphertext."""
        self._validate_key(key)
        iv, ciphertext = data[:self.IV_SIZE], data[self.IV_SIZE:]
        dec = self._build_cipher(key, iv).decryptor()
        try:
            return self._unpad(dec.update(ciphertext) + dec.finalize()).decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed — wrong key or corrupted data.")

    def encrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        self._validate_key(key)
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        iv  = self.generate_iv()
        enc = self._build_cipher(key, iv).encryptor()
        with open(input_path, "rb") as f:
            raw = f.read()
        with open(output_path, "wb") as f:
            f.write(iv + enc.update(self._pad(raw)) + enc.finalize())

    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        self._validate_key(key)
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        with open(input_path, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:self.IV_SIZE], data[self.IV_SIZE:]
        dec = self._build_cipher(key, iv).decryptor()
        try:
            plain = self._unpad(dec.update(ciphertext) + dec.finalize())
        except Exception:
            raise ValueError("File decryption failed — wrong key or corrupted file.")
        with open(output_path, "wb") as f:
            f.write(plain)

    @staticmethod
    def key_to_hex(key: bytes) -> str:
        return key.hex()

    @staticmethod
    def key_from_hex(hex_str: str) -> bytes:
        try:
            key = bytes.fromhex(hex_str.strip())
        except ValueError:
            raise ValueError("Invalid hex string for AES key.")
        if len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricCipher.KEY_SIZE} bytes. Got {len(key)}.")
        return key

    def key_from_password(self, password: str, salt: bytes = None, iterations: int = 310_000) -> tuple:
        """Derive a 256-bit AES key from password using PBKDF2-HMAC-SHA256. Returns (key, salt)."""
        import hashlib
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
        return key, salt

    def _build_cipher(self, key: bytes, iv: bytes) -> Cipher:
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def _pad(self, data: bytes) -> bytes:
        p = padding.PKCS7(self.BLOCK_SIZE * 8).padder()
        return p.update(data) + p.finalize()

    def _unpad(self, data: bytes) -> bytes:
        u = padding.PKCS7(self.BLOCK_SIZE * 8).unpadder()
        return u.update(data) + u.finalize()

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(f"AES key must be exactly {SymmetricCipher.KEY_SIZE} bytes.")
