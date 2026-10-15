"""
DIT 2104 - Task 6(b) Cryptographic prototype
Microfinance institution: protecting a sample customer record.

Demonstrates:
  1. AES-256-GCM encryption / decryption
  2. RSA-2048 (and ECDSA P-256) key generation + digital signature
  3. SHA-256 hashing and HMAC-SHA256 for integrity
  4. Size and execution-time comparison of the three operations
Uses only vetted libraries (cryptography, hashlib, hmac) - no primitives from scratch.
"""
import csv
import hashlib
import hmac
import json
import os
import statistics
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RUNS = 200  # repetitions per timed operation

SAMPLE_RECORD = {
    "customer_id": "UG-FP-004521",
    "name": "Akello Grace",
    "national_id": "CF9012345678AB",
    "phone": "+256772000111",
    "account_no": "0012345678",
    "branch": "Fort Portal",
    "balance_ugx": 2450000,
    "loan_outstanding_ugx": 800000,
}


def timed(fn, runs=RUNS):
    """Return (last_result, mean_ms, stdev_ms) over `runs` calls."""
    samples, result = [], None
    for _ in range(runs):
        t0 = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return result, statistics.mean(samples), statistics.pstdev(samples)


def hexshort(b, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "")


def main():
    record_bytes = json.dumps(SAMPLE_RECORD, sort_keys=True).encode()
    print("=" * 64)
    print("SAMPLE CUSTOMER RECORD (plaintext)")
    print("=" * 64)
    print(json.dumps(SAMPLE_RECORD, indent=2))
    print(f"Plaintext size: {len(record_bytes)} bytes\n")

    # ---------------- 1. AES-256-GCM ----------------
    print("-" * 64, "\n1. AES-256-GCM (confidentiality + integrity, data at rest)")
    key = AESGCM.generate_key(bit_length=256)      # 32-byte key
    aes = AESGCM(key)
    header = b"branch=Fort Portal"                  # authenticated, not encrypted

    def aes_encrypt():
        nonce = os.urandom(12)                      # unique per encryption
        return nonce, aes.encrypt(nonce, record_bytes, header)

    (nonce, ciphertext), t_enc, s_enc = timed(aes_encrypt)
    _, t_dec, s_dec = timed(lambda: aes.decrypt(nonce, ciphertext, header))
    recovered = aes.decrypt(nonce, ciphertext, header)
    assert recovered == record_bytes
    print(f"Key size        : {len(key)*8} bits")
    print(f"Nonce           : {nonce.hex()}")
    print(f"Ciphertext+tag  : {hexshort(ciphertext)} ({len(ciphertext)} bytes)")
    print("Decryption OK   : record recovered exactly")
    # tamper test
    bad = bytearray(ciphertext); bad[0] ^= 1
    try:
        aes.decrypt(nonce, bytes(bad), header)
        print("Tamper test     : FAILED (should not decrypt)")
    except Exception:
        print("Tamper test     : modified ciphertext REJECTED (GCM tag check)")

    # ---------------- 2. RSA + ECDSA signatures ----------------
    print("\n" + "-" * 64, "\n2. Digital signatures (authenticity + non-repudiation)")
    t0 = time.perf_counter()
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t_rsa_keygen = (time.perf_counter() - t0) * 1000
    rsa_pub = rsa_priv.public_key()
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

    rsa_sig, t_rsa_sign, s_rsa_sign = timed(lambda: rsa_priv.sign(record_bytes, pss, hashes.SHA256()))

    def rsa_verify():
        rsa_pub.verify(rsa_sig, record_bytes, pss, hashes.SHA256())
    _, t_rsa_ver, s_rsa_ver = timed(rsa_verify)

    t0 = time.perf_counter()
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    t_ec_keygen = (time.perf_counter() - t0) * 1000
    ec_pub = ec_priv.public_key()
    ec_sig, t_ec_sign, s_ec_sign = timed(lambda: ec_priv.sign(record_bytes, ec.ECDSA(hashes.SHA256())))
    _, t_ec_ver, s_ec_ver = timed(lambda: ec_pub.verify(ec_sig, record_bytes, ec.ECDSA(hashes.SHA256())))

    print(f"RSA-2048 signature : {hexshort(rsa_sig)} ({len(rsa_sig)} bytes) - verified")
    print(f"ECDSA P-256 sig    : {hexshort(ec_sig)} ({len(ec_sig)} bytes) - verified")
    tampered = record_bytes.replace(b"2450000", b"9450000")
    try:
        rsa_pub.verify(rsa_sig, tampered, pss, hashes.SHA256())
        print("Tamper test        : FAILED")
    except InvalidSignature:
        print("Tamper test        : altered balance -> signature INVALID")

    # ---------------- 3. SHA-256 + HMAC ----------------
    print("\n" + "-" * 64, "\n3. SHA-256 hash and HMAC-SHA256 (integrity)")
    digest, t_sha, s_sha = timed(lambda: hashlib.sha256(record_bytes).digest())
    hmac_key = os.urandom(32)
    tag, t_hmac, s_hmac = timed(lambda: hmac.new(hmac_key, record_bytes, hashlib.sha256).digest())
    print(f"SHA-256 digest : {digest.hex()}")
    print(f"HMAC-SHA256 tag: {tag.hex()}")
    ok = hmac.compare_digest(tag, hmac.new(hmac_key, record_bytes, hashlib.sha256).digest())
    print(f"HMAC verify    : {'VALID' if ok else 'INVALID'} (constant-time compare)")
    forged = hmac.new(os.urandom(32), record_bytes, hashlib.sha256).digest()
    print(f"Wrong-key HMAC : {'accepted (BAD)' if hmac.compare_digest(tag, forged) else 'rejected'}")

    # ---------------- Tokenisation (6a extra) ----------------
    token = "TKN-" + hmac.new(hmac_key, SAMPLE_RECORD["account_no"].encode(), hashlib.sha256).hexdigest()[:12].upper()
    print(f"\nTokenised account no. (for logs/reports): {SAMPLE_RECORD['account_no']} -> {token}")

    # ---------------- 4. Comparison ----------------
    rows = [
        ("AES-256-GCM encrypt", len(record_bytes), len(ciphertext), t_enc, s_enc),
        ("AES-256-GCM decrypt", len(ciphertext), len(record_bytes), t_dec, s_dec),
        ("RSA-2048 sign (PSS)", len(record_bytes), len(rsa_sig), t_rsa_sign, s_rsa_sign),
        ("RSA-2048 verify", len(rsa_sig), 1, t_rsa_ver, s_rsa_ver),
        ("ECDSA P-256 sign", len(record_bytes), len(ec_sig), t_ec_sign, s_ec_sign),
        ("ECDSA P-256 verify", len(ec_sig), 1, t_ec_ver, s_ec_ver),
        ("SHA-256 hash", len(record_bytes), len(digest), t_sha, s_sha),
        ("HMAC-SHA256", len(record_bytes), len(tag), t_hmac, s_hmac),
    ]
    print("\n" + "=" * 64)
    print(f"4. COMPARISON (mean of {RUNS} runs)")
    print("=" * 64)
    print(f"{'Operation':<22}{'In (B)':>8}{'Out (B)':>9}{'Mean ms':>12}{'Std ms':>10}")
    for name, i, o, m, s in rows:
        print(f"{name:<22}{i:>8}{o:>9}{m:>12.4f}{s:>10.4f}")
    print(f"\nOne-off key generation: RSA-2048 = {t_rsa_keygen:.1f} ms, ECDSA P-256 = {t_ec_keygen:.2f} ms")
    print(f"Key/size note: AES key 32 B, HMAC key 32 B, RSA public key ~294 B (DER), "
          f"EC public key 65 B (uncompressed)")

    with open("results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["operation", "input_bytes", "output_bytes", "mean_ms", "stdev_ms"])
        for name, i, o, m, s in rows:
            w.writerow([name, i, o, f"{m:.4f}", f"{s:.4f}"])
        w.writerow(["RSA-2048 keygen (once)", "", "", f"{t_rsa_keygen:.2f}", ""])
        w.writerow(["ECDSA P-256 keygen (once)", "", "", f"{t_ec_keygen:.2f}", ""])
    print("\nResults saved to results.csv")


if __name__ == "__main__":
    main()
