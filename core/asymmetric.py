import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from core.symmetric import SymmetricCipher


class AsymmetricCipher:
    """RSA-2048/4096 with OAEP + Hybrid encryption. CIA: Confidentiality."""

    def generate_key_pair(self, key_size: int = 2048):
        """Returns (private_key, public_key)."""
        priv = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        return priv, priv.public_key()

    def encrypt(self, plaintext: bytes, public_key) -> bytes:
        return public_key.encrypt(plaintext, self._oaep())

    def decrypt(self, ciphertext: bytes, private_key) -> bytes:
        try:
            return private_key.decrypt(ciphertext, self._oaep())
        except Exception:
            raise ValueError("RSA decryption failed — wrong private key or corrupted data.")

    def hybrid_encrypt(self, plaintext: str, public_key) -> dict:
        """AES encrypts data, RSA encrypts AES key. Returns {'encrypted_aes_key', 'ciphertext'}."""
        sym     = SymmetricCipher()
        aes_key = sym.generate_key()
        return {
            "encrypted_aes_key": self.encrypt(aes_key, public_key),
            "ciphertext":        sym.encrypt_text(plaintext, aes_key),
        }

    def hybrid_decrypt(self, encrypted_aes_key: bytes, ciphertext: bytes, private_key) -> str:
        aes_key = self.decrypt(encrypted_aes_key, private_key)
        return SymmetricCipher().decrypt_text(ciphertext, aes_key)

    def private_key_to_pem(self, private_key, password: bytes = None) -> bytes:
        enc = (serialization.BestAvailableEncryption(password)
               if password else serialization.NoEncryption())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc
        )

    def public_key_to_pem(self, public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_key_from_pem(self, pem: bytes, password: bytes = None):
        try:
            return serialization.load_pem_private_key(pem, password=password, backend=default_backend())
        except Exception:
            raise ValueError("Failed to load private key — invalid PEM or wrong password.")

    def public_key_from_pem(self, pem: bytes):
        try:
            return serialization.load_pem_public_key(pem, backend=default_backend())
        except Exception:
            raise ValueError("Failed to load public key — invalid PEM data.")

    def save_keys(self, private_key, public_key, directory: str = "keys") -> tuple:
        os.makedirs(directory, exist_ok=True)
        priv_path = os.path.join(directory, "private_key.pem")
        pub_path  = os.path.join(directory, "public_key.pem")
        with open(priv_path, "wb") as f:
            f.write(self.private_key_to_pem(private_key))
        with open(pub_path, "wb") as f:
            f.write(self.public_key_to_pem(public_key))
        return priv_path, pub_path

    @staticmethod
    def _oaep():
        return asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
