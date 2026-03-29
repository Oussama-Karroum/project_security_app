"""
Module: hashing.py
Class:  HashManager
Algo:   SHA-256
Libs:   hashlib, os
"""

import hashlib
import os


class HashManager:
    """
    Implements cryptographic hashing using SHA-256.

    A hash function produces a fixed-size digest from any input.
    Any modification to the input — even a single bit — produces
    a completely different digest (avalanche effect).

    CIA Target : Integrity
    Limit      : Hashing is one-way (cannot recover original data from hash)
                 Does NOT provide confidentiality or authentication alone
    """

    ALGORITHM = "sha256"

    # ------------------------------------------------------------------
    # Core hashing
    # ------------------------------------------------------------------

    def hash_text(self, text: str) -> str:
        """
        Compute the SHA-256 digest of a UTF-8 string.

        Args:
            text (str): Input message

        Returns:
            str: 64-character hex digest
        """
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        """
        Compute the SHA-256 digest of raw bytes.

        Args:
            data (bytes): Input bytes

        Returns:
            str: 64-character hex digest
        """
        return hashlib.sha256(data).hexdigest()

    def hash_file(self, path: str) -> str:
        """
        Compute the SHA-256 digest of a file (streaming, memory efficient).

        Reads the file in 64KB chunks so large files are handled safely.

        Args:
            path (str): Path to the file

        Returns:
            str: 64-character hex digest

        Raises:
            FileNotFoundError: If the file does not exist
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    def verify_text_integrity(self, text: str, expected_hash: str) -> bool:
        """
        Verify that a text's hash matches the expected digest.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            text          (str): Text to verify
            expected_hash (str): Previously computed SHA-256 hex digest

        Returns:
            bool: True if integrity is confirmed, False if tampered
        """
        computed = self.hash_text(text)
        return self._secure_compare(computed, expected_hash)

    def verify_file_integrity(self, path: str, expected_hash: str) -> bool:
        """
        Verify that a file's hash matches the expected digest.

        Args:
            path          (str): Path to the file
            expected_hash (str): Previously computed SHA-256 hex digest

        Returns:
            bool: True if integrity is confirmed, False if tampered
        """
        computed = self.hash_file(path)
        return self._secure_compare(computed, expected_hash)

    # ------------------------------------------------------------------
    # Tampering simulation (pedagogical)
    # ------------------------------------------------------------------

    def simulate_tampering(self, text: str) -> str:
        """
        Simulate a minimal tampering attack by flipping the last character.

        This demonstrates the avalanche effect:
        a tiny change produces a completely different hash.

        Args:
            text (str): Original text

        Returns:
            str: Slightly modified text
        """
        if not text:
            return text + "!"
        # Flip the last character's ASCII value by 1
        tampered = text[:-1] + chr(ord(text[-1]) ^ 1)
        return tampered

    def compare_hashes(self, original: str, modified: str) -> dict:
        """
        Compute and compare hashes of two texts side by side.

        Useful for pedagogical demonstration of the avalanche effect.

        Args:
            original (str): Original text
            modified (str): Modified (tampered) text

        Returns:
            dict: {
                'original_hash':  str,
                'modified_hash':  str,
                'match':          bool,
                'diff_bits':      int,   # number of differing hex chars
            }
        """
        h1 = self.hash_text(original)
        h2 = self.hash_text(modified)

        diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))

        return {
            "original_hash": h1,
            "modified_hash": h2,
            "match":         h1 == h2,
            "diff_chars":    diff,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _secure_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        Uses hmac.compare_digest internally.
        """
        import hmac
        return hmac.compare_digest(a.encode(), b.encode())