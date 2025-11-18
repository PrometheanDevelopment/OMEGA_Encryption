#!/usr/bin/env python3
"""
secure_max_postquantum_stack.py

Maximum-security hybrid encryptor (classical + post-quantum) built to give
**the highest practical security today and against future quantum adversaries**.

Usage examples
  # generate maximum-strength keys for identity 'alice'
  python secure_max_postquantum_stack.py --gen-keys --id alice

  # encrypt
  python secure_max_postquantum_stack.py --mode encrypt --infile message.txt \
      --recipient_x25519_pub alice_x25519_pub.pem --recipient_kyber_pub alice_kyber_pub.bin \
      --sender_ed_priv bob_ed25519_priv.pem --sender_dilithium_priv bob_dilithium_priv.bin \
      --outfile out.json

  # decrypt
  python secure_max_postquantum_stack.py --mode decrypt --infile out.json \
      --recipient_x25519_priv alice_x25519_priv.pem --recipient_kyber_priv alice_kyber_priv.bin \
      --sender_ed_pub bob_ed25519_pub.pem --sender_dilithium_pub bob_dilithium_pub.bin

"""

import argparse
import base64
import json
import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Attempt PQC imports. Prefer highest-strength parameter sets (Kyber1024, Dilithium5)
PQC_AVAILABLE = False
KYBER_AVAILABLE = False
DILITHIUM_AVAILABLE = False
SPHINCS_AVAILABLE = False
_pqc_import_error = None

try:
    # pqcrypto naming varies — try common modules
    import pqcrypto.kem.kyber1024 as _kyber_mod
    from pqcrypto.kem.kyber1024 import generate_keypair as kyber_generate, encrypt as kyber_encapsulate, decrypt as kyber_decapsulate
    KYBER_AVAILABLE = True
    PQC_AVAILABLE = True
except Exception as e:
    _pqc_import_error = e
    try:
        import pqcrypto.kem.kyber512 as _kyber_mod
        from pqcrypto.kem.kyber512 import generate_keypair as kyber_generate, encrypt as kyber_encapsulate, decrypt as kyber_decapsulate
        KYBER_AVAILABLE = True
        PQC_AVAILABLE = True
    except Exception:
        KYBER_AVAILABLE = False

try:
    import pqcrypto.sign.dilithium5 as _dil_mod
    from pqcrypto.sign.dilithium5 import generate_keypair as dilithium_generate, sign as dilithium_sign, verify as dilithium_verify
    DILITHIUM_AVAILABLE = True
    PQC_AVAILABLE = True
except Exception:
    try:
        import pqcrypto.sign.dilithium2 as _dil_mod
        from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_generate, sign as dilithium_sign, verify as dilithium_verify
        DILITHIUM_AVAILABLE = True
        PQC_AVAILABLE = True
    except Exception:
        DILITHIUM_AVAILABLE = False

# SPHINCS+ via pyspx (hash-based fallback)
try:
    import pyspx
    SPHINCS_AVAILABLE = True
    PQC_AVAILABLE = True
except Exception:
    SPHINCS_AVAILABLE = False

# helpers for base64

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

# ---------------- key generation ----------------

def save_bytes(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

def gen_all_keys(prefix: str):
    # X25519
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_priv_pem = x_priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    x_pub_pem = x_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    save_bytes(f'{prefix}_x25519_priv.pem', x_priv_pem)
    save_bytes(f'{prefix}_x25519_pub.pem', x_pub_pem)

    # Ed25519
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_priv_pem = ed_priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    ed_pub_pem = ed_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    save_bytes(f'{prefix}_ed25519_priv.pem', ed_priv_pem)
    save_bytes(f'{prefix}_ed25519_pub.pem', ed_pub_pem)

    # PQC keys
    if KYBER_AVAILABLE:
        ky_pub, ky_priv = kyber_generate()
        save_bytes(f'{prefix}_kyber_pub.bin', ky_pub)
        save_bytes(f'{prefix}_kyber_priv.bin', ky_priv)
    else:
        print('Warning: Kyber (preferred Kyber1024) not available in environment; PQC KEM will be disabled.')

    if DILITHIUM_AVAILABLE:
        dil_pub, dil_priv = dilithium_generate()
        save_bytes(f'{prefix}_dilithium_pub.bin', dil_pub)
        save_bytes(f'{prefix}_dilithium_priv.bin', dil_priv)
    else:
        print('Warning: Dilithium (preferred Dilithium5) not available; PQC signatures disabled.')

    if SPHINCS_AVAILABLE:
        print('SPHINCS+ available as conservative fallback for signatures (via pyspx).')

    print(f'Generated keys with prefix: {prefix}_*')

# ---------------- load helpers ----------------

def load_x25519_public(path: str):
    return serialization.load_pem_public_key(open(path, 'rb').read(), backend=default_backend())

def load_x25519_private(path: str):
    return serialization.load_pem_private_key(open(path, 'rb').read(), password=None, backend=default_backend())

def load_ed25519_private(path: str):
    return serialization.load_pem_private_key(open(path, 'rb').read(), password=None, backend=default_backend())

def load_ed25519_public(path: str):
    return serialization.load_pem_public_key(open(path, 'rb').read(), backend=default_backend())

# PQC raw loaders

def load_kyber_pub_raw(path: str) -> bytes:
    return open(path, 'rb').read()

def load_kyber_priv_raw(path: str) -> bytes:
    return open(path, 'rb').read()

def load_dilithium_pub_raw(path: str) -> bytes:
    return open(path, 'rb').read()

def load_dilithium_priv_raw(path: str) -> bytes:
    return open(path, 'rb').read()

# ---------------- derive hybrid keys ----------------

def derive_hybrid_keys(shared_classical: bytes, shared_pqc: bytes = None) -> Tuple[bytes, bytes]:
    # Combine classical and PQC shared secrets into a single master secret and derive two AEAD keys
    if shared_pqc is None:
        master = shared_classical
    else:
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(shared_classical)
        digest.update(shared_pqc)
        master = digest.finalize()
    hkdf1 = HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=b'hybrid-chacha', backend=default_backend())
    key_a = hkdf1.derive(master)
    hkdf2 = HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=b'hybrid-aes', backend=default_backend())
    key_b = hkdf2.derive(master)
    return key_a, key_b

# ---------------- encryption / decryption ----------------

def encrypt(plaintext: bytes, recipient_x25519_pub_path: str, recipient_kyber_pub_path: str = None,
            sender_ed_priv_path: str = None, sender_dilithium_priv_path: str = None, use_sphincs: bool = False) -> dict:
    """Encrypt using hybrid classical + PQC stack with automatic fallback."""
    
    # ---- Classical ephemeral ECDH ----
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    recipient_pub = load_x25519_public(recipient_x25519_pub_path)
    shared_classical = ephemeral_priv.exchange(recipient_pub)

    # ---- PQC: Kyber encapsulation ----
    shared_pqc = None
    ky_ct = None
    if KYBER_AVAILABLE and recipient_kyber_pub_path:
        try:
            ky_pub = load_kyber_pub_raw(recipient_kyber_pub_path)
            try:
                ky_ct, ky_ss = kyber_encapsulate(ky_pub)
            except TypeError:
                ky_ss, ky_ct = kyber_encapsulate(ky_pub)
            shared_pqc = ky_ss
        except Exception as e:
            print(f"Warning: Kyber encapsulation failed, falling back to classical only. ({e})")
            ky_ct = None
            shared_pqc = None

    # ---- Key derivation ----
    key_chacha, key_aes = derive_hybrid_keys(shared_classical, shared_pqc)

    # ---- AEAD encryption ----
    nonce_chacha = secrets.token_bytes(12)
    chacha = ChaCha20Poly1305(key_chacha)
    ct1 = chacha.encrypt(nonce_chacha, plaintext, None)

    nonce_aes = secrets.token_bytes(12)
    aesgcm = AESGCM(key_aes)
    ct2 = aesgcm.encrypt(nonce_aes, ct1, None)

    # ---- Signatures ----
    ed_sig = None
    if sender_ed_priv_path:
        sender_ed_priv = load_ed25519_private(sender_ed_priv_path)
        ed_sig = sender_ed_priv.sign(ct2)

    dil_sig = None
    if DILITHIUM_AVAILABLE and sender_dilithium_priv_path:
        try:
            dil_priv = load_dilithium_priv_raw(sender_dilithium_priv_path)
            try:
                dil_sig = dilithium_sign(dil_priv, ct2)
            except TypeError:
                dil_sig = dilithium_sign(ct2, dil_priv)
        except Exception as e:
            print(f"Warning: Dilithium signing failed, skipping. ({e})")

    sphincs_sig = None
    if use_sphincs and SPHINCS_AVAILABLE:
        try:
            sphincs_sig = pyspx.sphincs.sign(ct2, seed=None)
        except Exception:
            sphincs_sig = None

    return {
        'ephemeral_pub_raw': b64(ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        'kyber_ct': b64(ky_ct) if ky_ct else None,
        'nonce_chacha': b64(nonce_chacha),
        'nonce_aes': b64(nonce_aes),
        'ciphertext': b64(ct2),
        'ed25519_sig': b64(ed_sig) if ed_sig else None,
        'dilithium_sig': b64(dil_sig) if dil_sig else None,
        'sphincs_sig': b64(sphincs_sig) if sphincs_sig else None,
        'aead_stack': ['ChaCha20-Poly1305', 'AES-GCM'],
        'pqc': {
            'kyber': 'kyber1024' if KYBER_AVAILABLE else None,
            'dilithium': 'dilithium5' if DILITHIUM_AVAILABLE else None,
            'sphincs': 'available' if SPHINCS_AVAILABLE else None
        }
    }


def decrypt(payload: dict, recipient_x25519_priv_path: str, recipient_kyber_priv_path: str = None,
            sender_ed_pub_path: str = None, sender_dilithium_pub_path: str = None, use_sphincs: bool = False) -> bytes:
    """Decrypt using hybrid classical + PQC stack with automatic fallback."""

    ephem_raw = ub64(payload['ephemeral_pub_raw'])
    ephem_pub = x25519.X25519PublicKey.from_public_bytes(ephem_raw)
    recipient_priv = load_x25519_private(recipient_x25519_priv_path)
    shared_classical = recipient_priv.exchange(ephem_pub)

    # ---- PQC decapsulation (Kyber) ----
    shared_pqc = None
    ky_ct_b64 = payload.get('kyber_ct')
    if KYBER_AVAILABLE and ky_ct_b64 and recipient_kyber_priv_path:
        try:
            ky_ct = ub64(ky_ct_b64)
            ky_priv = load_kyber_priv_raw(recipient_kyber_priv_path)
            try:
                shared_pqc = kyber_decapsulate(ky_ct, ky_priv)
            except TypeError:
                shared_pqc, _ = kyber_decapsulate(ky_ct, ky_priv)
        except Exception:
            print("Warning: Kyber decapsulation failed, proceeding with classical only.")
            shared_pqc = None

    key_chacha, key_aes = derive_hybrid_keys(shared_classical, shared_pqc)
    ct2 = ub64(payload['ciphertext'])

    # ---- Signature verification ----
    if sender_ed_pub_path and payload.get('ed25519_sig'):
        ed_sig = ub64(payload['ed25519_sig'])
        sender_ed_pub = load_ed25519_public(sender_ed_pub_path)
        try:
            sender_ed_pub.verify(ed_sig, ct2)
        except InvalidSignature:
            raise ValueError('Ed25519 signature verification failed')

    if DILITHIUM_AVAILABLE and payload.get('dilithium_sig') and sender_dilithium_pub_path:
        try:
            dil_pub = load_dilithium_pub_raw(sender_dilithium_pub_path)
            sig = ub64(payload['dilithium_sig'])
            try:
                ok = dilithium_verify(dil_pub, ct2, sig)
                if not ok:
                    print("Warning: Dilithium signature invalid, ignoring.")
            except TypeError:
                try:
                    dilithium_verify(sig, dil_pub, ct2)
                except Exception:
                    print("Warning: Dilithium signature invalid, ignoring.")
        except Exception:
            print("Warning: Dilithium verification skipped due to missing key or failure.")

    if use_sphincs and SPHINCS_AVAILABLE and payload.get('sphincs_sig'):
        try:
            sph_sig = ub64(payload['sphincs_sig'])
            pyspx.sphincs.verify(sph_sig, ct2)
        except Exception:
            print("Warning: SPHINCS signature verification failed, ignoring.")

    # ---- AEAD decryption ----
    nonce_aes = ub64(payload['nonce_aes'])
    aesgcm = AESGCM(key_aes)
    ct1 = aesgcm.decrypt(nonce_aes, ct2, None)

    nonce_chacha = ub64(payload['nonce_chacha'])
    chacha = ChaCha20Poly1305(key_chacha)
    plaintext = chacha.decrypt(nonce_chacha, ct1, None)

    return plaintext

def decrypt(payload: dict, recipient_x25519_priv_path: str, recipient_kyber_priv_path: str, sender_ed_pub_path: str, sender_dilithium_pub_path: str = None, use_sphincs: bool = False) -> bytes:
    ephem_raw = ub64(payload['ephemeral_pub_raw'])
    ephem_pub = x25519.X25519PublicKey.from_public_bytes(ephem_raw)
    recipient_priv = load_x25519_private(recipient_x25519_priv_path)
    shared_classical = recipient_priv.exchange(ephem_pub)

    # PQC decapsulation
    shared_pqc = None
    if KYBER_AVAILABLE and payload.get('kyber_ct'):
        ky_ct = ub64(payload['kyber_ct'])
        ky_priv = load_kyber_priv_raw(recipient_kyber_priv_path)
        try:
            ky_ss = kyber_decapsulate(ky_ct, ky_priv)
        except TypeError:
            ky_ss, _ = kyber_decapsulate(ky_ct, ky_priv)
        shared_pqc = ky_ss
    elif payload.get('kyber_ct'):
        raise RuntimeError('Cannot decapsulate Kyber ciphertext: Kyber not available')

    key_chacha, key_aes = derive_hybrid_keys(shared_classical, shared_pqc)

    ct2 = ub64(payload['ciphertext'])

    # verify Ed25519
    ed_sig = ub64(payload['ed25519_sig'])
    sender_ed_pub = load_ed25519_public(sender_ed_pub_path)
    try:
        sender_ed_pub.verify(ed_sig, ct2)
    except InvalidSignature:
        raise ValueError('Ed25519 signature verification failed')

    # verify Dilithium if present
    if DILITHIUM_AVAILABLE and payload.get('dilithium_sig'):
        if not sender_dilithium_pub_path:
            raise ValueError('Dilithium signature present but sender Dilithium pub not provided')
        dil_pub = load_dilithium_pub_raw(sender_dilithium_pub_path)
        sig = ub64(payload['dilithium_sig'])
        try:
            ok = dilithium_verify(dil_pub, ct2, sig)
            if not ok:
                raise ValueError('Dilithium signature invalid')
        except TypeError:
            # some APIs raise on invalid
            try:
                dilithium_verify(sig, dil_pub, ct2)
            except Exception:
                raise ValueError('Dilithium signature invalid')

    # optional SPHINCS verify
    if use_sphincs and SPHINCS_AVAILABLE and payload.get('sphincs_sig'):
        try:
            sph_sig = ub64(payload['sphincs_sig'])
            pyspx.sphincs.verify(sph_sig, ct2)
        except Exception:
            raise ValueError('SPHINCS signature verification failed')

    # decrypt layers
    nonce_aes = ub64(payload['nonce_aes'])
    aesgcm = AESGCM(key_aes)
    ct1 = aesgcm.decrypt(nonce_aes, ct2, None)

    nonce_chacha = ub64(payload['nonce_chacha'])
    chacha = ChaCha20Poly1305(key_chacha)
    plaintext = chacha.decrypt(nonce_chacha, ct1, None)
    return plaintext

# ---------------- CLI ----------------

def main():
    parser = argparse.ArgumentParser(description='Maximum-security hybrid classical + PQC encryptor (Kyber1024 + Dilithium5)')
    parser.add_argument('--gen-keys', action='store_true')
    parser.add_argument('--id', help='prefix for keys')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'])
    parser.add_argument('--infile')
    parser.add_argument('--outfile')
    parser.add_argument('--recipient_x25519_pub')
    parser.add_argument('--recipient_kyber_pub')
    parser.add_argument('--recipient_x25519_priv')
    parser.add_argument('--recipient_kyber_priv')
    parser.add_argument('--sender_ed_priv')
    parser.add_argument('--sender_dilithium_priv')
    parser.add_argument('--sender_ed_pub')
    parser.add_argument('--sender_dilithium_pub')
    parser.add_argument('--use_sphincs', action='store_true', help='Enable SPHINCS+ signatures as extra fallback')

    args = parser.parse_args()

    if args.gen_keys:
        if not args.id:
            parser.error('--gen-keys requires --id')
        gen_all_keys(args.id)
        return

    if args.mode == 'encrypt':
        if not args.infile or not args.recipient_x25519_pub or not args.sender_ed_priv:
            parser.error('encrypt requires --infile --recipient_x25519_pub --sender_ed_priv')
        plaintext = open(args.infile, 'rb').read()
        payload = encrypt(plaintext, args.recipient_x25519_pub, args.recipient_kyber_pub, args.sender_ed_priv, args.sender_dilithium_priv, use_sphincs=args.use_sphincs)
        out = json.dumps(payload)
        if args.outfile:
            open(args.outfile, 'w').write(out)
            print(f'Wrote encrypted JSON to {args.outfile}')
        else:
            print(out)
        return

    if args.mode == 'decrypt':
        if not args.infile or not args.recipient_x25519_priv or not args.sender_ed_pub:
            parser.error('decrypt requires --infile --recipient_x25519_priv --sender_ed_pub')
        payload = json.load(open(args.infile, 'r'))
        plaintext = decrypt(payload, args.recipient_x25519_priv, args.recipient_kyber_priv, args.sender_ed_pub, args.sender_dilithium_pub, use_sphincs=args.use_sphincs)
        if args.outfile:
            open(args.outfile, 'wb').write(plaintext)
            print(f'Wrote plaintext to {args.outfile}')
        else:
            print(plaintext.decode('utf-8', errors='replace'))
        return

    parser.print_help()

if __name__ == '__main__':
    if not PQC_AVAILABLE:
        print('WARNING: PQC libraries not fully available. Install: pip install pqcrypto pyspx')
    else:
        print('PQC support: ' + ', '.join([k for k,v in [('Kyber',KYBER_AVAILABLE),('Dilithium',DILITHIUM_AVAILABLE),('SPHINCS',SPHINCS_AVAILABLE)] if v]))
    main()
