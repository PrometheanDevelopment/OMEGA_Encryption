# OMEGA_Encryption
OMEGA encryption - an encryption stack with 256 bit encryption and anti-quantum hardening.

Requirements:

- Python 3.8+
- `cryptography`
- A PQ KEM backend (optional — e.g., `pqcrypto`, `mlkem`, `kyber-py`)

# OMEGA — Hybrid Post-Quantum Encryption Library
**Omega Encryption v2.3 — X25519 + PQ KEM → HKDF → AES-256-GCM**

OMEGA, or "Omnisecret Multi-layer Encryption with GCM & Asymmetric X25519" is a lightweight, modern hybrid-encryption library designed to provide strong confidentiality against both classical and quantum adversaries. It combines elliptic-curve Diffie–Hellman (X25519) with an optional post-quantum KEM to derive high-entropy symmetric keys, which are then used with AES-256-GCM for authenticated encryption.

OMEGA is designed to be simple, auditable, and easy to integrate into new or existing projects.
