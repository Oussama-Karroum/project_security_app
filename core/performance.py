import time
from core.symmetric import SymmetricCipher
from core.asymmetric import AsymmetricCipher


class PerformanceAnalyzer:
    """Benchmarks AES-256-CBC vs RSA-2048 to demonstrate why hybrid encryption is standard."""

    def __init__(self):
        self.sym  = SymmetricCipher()
        self.asym = AsymmetricCipher()

    def benchmark_aes(self, text: str, iterations: int = 100) -> dict:
        t0 = time.perf_counter()
        for _ in range(iterations):
            key = self.sym.generate_key()
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        key = self.sym.generate_key()

        t0 = time.perf_counter()
        for _ in range(iterations):
            ct = self.sym.encrypt_text(text, key)
        enc_ms = (time.perf_counter() - t0) / iterations * 1000

        ct = self.sym.encrypt_text(text, key)

        t0 = time.perf_counter()
        for _ in range(iterations):
            self.sym.decrypt_text(ct, key)
        dec_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "algorithm":  "AES-256-CBC",
            "keygen_ms":  round(keygen_ms, 4),
            "encrypt_ms": round(enc_ms, 4),
            "decrypt_ms": round(dec_ms, 4),
            "total_ms":   round(keygen_ms + enc_ms + dec_ms, 4),
            "data_size":  len(text.encode("utf-8")),
            "iterations": iterations,
        }

    def benchmark_rsa(self, text: str, key_size: int = 2048, iterations: int = 5) -> dict:
        max_bytes = (key_size // 8) - 66
        payload   = text.encode("utf-8")[:max_bytes]

        t0 = time.perf_counter()
        for _ in range(iterations):
            priv, pub = self.asym.generate_key_pair(key_size)
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        priv, pub = self.asym.generate_key_pair(key_size)

        t0 = time.perf_counter()
        for _ in range(iterations):
            ct = self.asym.encrypt(payload, pub)
        enc_ms = (time.perf_counter() - t0) / iterations * 1000

        ct = self.asym.encrypt(payload, pub)

        t0 = time.perf_counter()
        for _ in range(iterations):
            self.asym.decrypt(ct, priv)
        dec_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "algorithm":  f"RSA-{key_size}",
            "keygen_ms":  round(keygen_ms, 4),
            "encrypt_ms": round(enc_ms, 4),
            "decrypt_ms": round(dec_ms, 4),
            "total_ms":   round(keygen_ms + enc_ms + dec_ms, 4),
            "data_size":  len(payload),
            "iterations": iterations,
        }

    def full_comparison(self, text: str) -> dict:
        aes = self.benchmark_aes(text, iterations=100)
        rsa = self.benchmark_rsa(text, iterations=5)
        speedup = rsa["total_ms"] / aes["total_ms"] if aes["total_ms"] > 0 else 0
        return {
            "aes":            aes,
            "rsa":            rsa,
            "speedup_factor": round(speedup, 1),
            "conclusion": (
                f"AES is approximately {speedup:.0f}x faster than RSA. "
                "This is why hybrid encryption is standard: AES encrypts data, RSA encrypts only the AES key."
            )
        }

    def format_report(self, results: dict) -> str:
        aes = results["aes"]
        rsa = results["rsa"]
        lines = [
            "╔══════════════════════════════════════════╗",
            "║       PERFORMANCE COMPARISON REPORT      ║",
            "╚══════════════════════════════════════════╝",
            "",
            f"  {'Metric':<20} {'AES-256-CBC':>15} {'RSA-2048':>15}",
            f"  {'─'*20} {'─'*15} {'─'*15}",
            f"  {'Key Generation':<20} {aes['keygen_ms']:>13.4f}ms {rsa['keygen_ms']:>13.4f}ms",
            f"  {'Encryption':<20} {aes['encrypt_ms']:>13.4f}ms {rsa['encrypt_ms']:>13.4f}ms",
            f"  {'Decryption':<20} {aes['decrypt_ms']:>13.4f}ms {rsa['decrypt_ms']:>13.4f}ms",
            f"  {'TOTAL':<20} {aes['total_ms']:>13.4f}ms {rsa['total_ms']:>13.4f}ms",
            "",
            f"  Speedup Factor : AES is ~{results['speedup_factor']}x faster than RSA",
            "",
            f"  Conclusion : {results['conclusion']}",
        ]
        return "\n".join(lines)
