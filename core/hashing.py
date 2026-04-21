import hashlib
import hmac
import os


class HashManager:
    """SHA-256 hashing and integrity verification. CIA: Integrity."""

    ALGORITHM = "sha256"

    def hash_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def hash_file(self, path: str) -> str:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def verify_text_integrity(self, text: str, expected_hash: str) -> bool:
        return hmac.compare_digest(self.hash_text(text).encode(), expected_hash.encode())

    def verify_file_integrity(self, path: str, expected_hash: str) -> bool:
        return hmac.compare_digest(self.hash_file(path).encode(), expected_hash.encode())

    def simulate_tampering(self, text: str) -> str:
        if not text:
            return text + "!"
        return text[:-1] + chr(ord(text[-1]) ^ 1)

    def compare_hashes(self, original: str, modified: str) -> dict:
        h1 = self.hash_text(original)
        h2 = self.hash_text(modified)
        return {
            "original_hash": h1,
            "modified_hash": h2,
            "match":         h1 == h2,
            "diff_chars":    sum(c1 != c2 for c1, c2 in zip(h1, h2)),
        }
