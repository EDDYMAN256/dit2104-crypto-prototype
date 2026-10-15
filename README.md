# DIT 2104 - Cryptographic Prototype (Task 6b)

Demonstrates AES-256-GCM, RSA-2048 / ECDSA P-256 digital signatures, SHA-256 and
HMAC-SHA256 on a sample microfinance customer record, with a size and timing comparison.

## Requirements
- Python 3.9+
- `pip install -r requirements.txt`

## Run
```
python crypto_demo.py
```
Output is printed to the terminal and a timing table is saved to `results.csv`.

## What it shows
1. AES-256-GCM encrypt/decrypt + tamper test (modified ciphertext is rejected)
2. RSA-2048 (PSS) and ECDSA P-256 signatures + tamper test (altered balance invalidates signature)
3. SHA-256 digest and HMAC-SHA256 tag with constant-time verification
4. Tokenisation of the account number (HMAC-based) for logs and reports
5. Table of input/output sizes and mean execution time (200 runs each)

## Notes
- Uses the `cryptography` library and Python's `hashlib`/`hmac`; no primitives are implemented from scratch.
- Keys are generated fresh each run and kept in memory only. In production keys would live in an HSM/KMS.
- Repository link: <add your Git repo URL here>
