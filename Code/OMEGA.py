#!/usr/bin/env python3
"""
secure_stack_encryptor.py

A hardened "stacked" hybrid encryption tool that layers modern, well-regarded primitives.

Pipeline (encryption):
  1) Ephemeral X25519 ECDH -> shared secret
  2) HKDF(SHA256) derives two independent symmetric keys
     - Key A -> ChaCha20-Poly1305 (primary AEAD)
     - Key B -> AES-GCM (secondary AEAD layered on top)
  3) Sign the final ciphertext with Ed25519 (sender authenticity)

Decryption reverses the steps and verifies the signature.

Security features:
  - Uses X25519 (Curve25519) for ECDH (forward secrecy via ephemeral keys).
  - Uses HKDF to derive independent keys for each AEAD primitive.
  - Uses ChaCha20-Poly1305 and AES-GCM (two independent AEADs stacked).
  - Adds Ed25519 signatures for sender authentication and integrity.
  - Optional Scrypt-based password protection when generating private keys.
  - Output is a compact JSON blob with base64-encoded fields; safe to transmit.

Dependencies:
  pip install cryptography

Usage examples:
  # generate keypairs for recipient (decryption) and sender (signing)
  python secure_stack_encryptor.py --gen-keys --recipient-id recipient --sender-id sender

  # encrypt a message
  python secure_stack_encryptor.py --mode encrypt --infile message.txt --recipient recipient_public.pem --sender sender_private.pem --out out.json

  # decrypt
  python secure_stack_encryptor.py --mode decrypt --infile out.json --recipient recipient_private.pem --sender sender_public.pem

Notes:
  - Keep private keys safe. If you protect them with a password when generating, remember the password.
  - This script aims to be robust and opinionated for demonstration; for production use, prefer well-tested libraries/protocols (libsodium, age, PGP, TLS).

"""

import argparse
import base64
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets

# ----------------- Utility helpers -----------------

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

# ----------------- Key generation / storage -----------------

def save_private_key_bytes(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

def save_public_key_bytes(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

def gen_keypair_x25519(prefix: str, protect_password: str = None):
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    # serialize
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if protect_password:
        # derive key from password with scrypt and encrypt the PEM with a simple XOR (note: for real use, use proper PEM encryption)
        # We'll instead store a scrypt-derived key and use it to encrypt the private bytes using ChaCha20Poly1305
        salt = secrets.token_bytes(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(protect_password.encode('utf-8'))
        aead = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aead.encrypt(nonce, priv_bytes, None)
        # store salt|nonce|ciphertext in base64-wrapped JSON
        payload = {'scrypt_salt': b64(salt), 'nonce': b64(nonce), 'priv_enc': b64(ciphertext)}
        save_private_key_bytes(f'{prefix}_x25519_priv.json', json.dumps(payload).encode('utf-8'))
    else:
        save_private_key_bytes(f'{prefix}_x25519_priv.pem', priv_bytes)
    save_public_key_bytes(f'{prefix}_x25519_pub.pem', pub_bytes)
    print(f'Generated X25519 keys: {prefix}_x25519_priv.* , {prefix}_x25519_pub.pem')

def gen_keypair_ed25519(prefix: str, protect_password: str = None):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if protect_password:
        salt = secrets.token_bytes(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(protect_password.encode('utf-8'))
        aead = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aead.encrypt(nonce, priv_bytes, None)
        payload = {'scrypt_salt': b64(salt), 'nonce': b64(nonce), 'priv_enc': b64(ciphertext)}
        save_private_key_bytes(f'{prefix}_ed25519_priv.json', json.dumps(payload).encode('utf-8'))
    else:
        save_private_key_bytes(f'{prefix}_ed25519_priv.pem', priv_bytes)
    save_public_key_bytes(f'{prefix}_ed25519_pub.pem', pub_bytes)
    print(f'Generated Ed25519 keys: {prefix}_ed25519_priv.* , {prefix}_ed25519_pub.pem')

# load helpers (support both raw PEM and scrypt-protected JSON)

def load_x25519_private(path_priv: str, password: str = None) -> x25519.X25519PrivateKey:
    if path_priv.endswith('.json'):
        data = json.load(open(path_priv, 'rb'))
        salt = ub64(data['scrypt_salt'])
        nonce = ub64(data['nonce'])
        priv_enc = ub64(data['priv_enc'])
        if password is None:
            raise ValueError('Password required to decrypt protected private key')
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
        aead = ChaCha20Poly1305(key)
        priv_bytes = aead.decrypt(nonce, priv_enc, None)
    else:
        priv_bytes = open(path_priv, 'rb').read()
    return serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())

def load_x25519_public(path_pub: str) -> x25519.X25519PublicKey:
    data = open(path_pub, 'rb').read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def load_ed25519_private(path_priv: str, password: str = None) -> ed25519.Ed25519PrivateKey:
    if path_priv.endswith('.json'):
        data = json.load(open(path_priv, 'rb'))
        salt = ub64(data['scrypt_salt'])
        nonce = ub64(data['nonce'])
        priv_enc = ub64(data['priv_enc'])
        if password is None:
            raise ValueError('Password required to decrypt protected private key')
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
        aead = ChaCha20Poly1305(key)
        priv_bytes = aead.decrypt(nonce, priv_enc, None)
    else:
        priv_bytes = open(path_priv, 'rb').read()
    return serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())

def load_ed25519_public(path_pub: str) -> ed25519.Ed25519PublicKey:
    data = open(path_pub, 'rb').read()
    return serialization.load_pem_public_key(data, backend=default_backend())

# ----------------- Core hybrid layered encryption -----------------

def derive_keys(shared_secret: bytes) -> Tuple[bytes, bytes]:
    # Derive two independent 32-byte keys using HKDF with distinct info labels
    hkdf_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake chacha', backend=default_backend())
    key_a = hkdf_a.derive(shared_secret)
    hkdf_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake aes', backend=default_backend())
    key_b = hkdf_b.derive(shared_secret)
    return key_a, key_b


def encrypt(plaintext: bytes, recipient_pub: x25519.X25519PublicKey, sender_ed_priv: ed25519.Ed25519PrivateKey) -> dict:
    # ephemeral ECDH
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    shared = ephemeral_priv.exchange(recipient_pub)
    key_chacha, key_aes = derive_keys(shared)

    # ChaCha20-Poly1305 encrypt first
    nonce_chacha = secrets.token_bytes(12)
    chacha = ChaCha20Poly1305(key_chacha)
    ct1 = chacha.encrypt(nonce_chacha, plaintext, None)

    # AES-GCM encrypt the result
    nonce_aes = secrets.token_bytes(12)
    aesgcm = AESGCM(key_aes)
    ct2 = aesgcm.encrypt(nonce_aes, ct1, None)

    # Sign the final ciphertext (ct2) with sender's Ed25519
    signature = sender_ed_priv.sign(ct2)

    out = {
        'ephemeral_pub': b64(ephemeral_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        'nonce_chacha': b64(nonce_chacha),
        'nonce_aes': b64(nonce_aes),
        'ciphertext': b64(ct2),
        'signature': b64(signature),
        'sender_pub_ed25519': b64(sender_ed_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        'kdf': 'HKDF-SHA256',
        'aead_stack': ['ChaCha20-Poly1305', 'AES-GCM']
    }
    return out


def decrypt(payload: dict, recipient_priv: x25519.X25519PrivateKey, sender_pub: ed25519.Ed25519PublicKey) -> bytes:
    ephemeral_pub_raw = ub64(payload['ephemeral_pub'])
    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_raw)
    shared = recipient_priv.exchange(ephemeral_pub)
    key_chacha, key_aes = derive_keys(shared)

    ct2 = ub64(payload['ciphertext'])
    # verify signature
    sig = ub64(payload['signature'])
    try:
        sender_pub.verify(sig, ct2)
    except InvalidSignature:
        raise ValueError('Invalid signature: sender authenticity cannot be verified')

    nonce_aes = ub64(payload['nonce_aes'])
    aesgcm = AESGCM(key_aes)
    ct1 = aesgcm.decrypt(nonce_aes, ct2, None)

    nonce_chacha = ub64(payload['nonce_chacha'])
    chacha = ChaCha20Poly1305(key_chacha)
    plaintext = chacha.decrypt(nonce_chacha, ct1, None)
    return plaintext

# ----------------- CLI -----------------

def main():
    parser = argparse.ArgumentParser(description='Secure layered hybrid encryptor')
    parser.add_argument('--gen-keys', action='store_true', help='Generate keypairs for recipient and sender')
    parser.add_argument('--recipient-id', help='Prefix for recipient key files when generating')
    parser.add_argument('--sender-id', help='Prefix for sender key files when generating')
    parser.add_argument('--protect-password', help='Optional password to protect generated private keys (scrypt-based)')

    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], help='Mode')
    parser.add_argument('--infile', help='Input file (plaintext for encrypt, JSON for decrypt)')
    parser.add_argument('--outfile', help='Output file (JSON for encrypt, plaintext for decrypt)')
    parser.add_argument('--recipient', help='Recipient public (encrypt) or private (decrypt) key path')
    parser.add_argument('--sender', help='Sender private (encrypt) or public (decrypt) key path')
    parser.add_argument('--password', help='Password to decrypt protected private keys (if applicable)')

    args = parser.parse_args()

    if args.gen_keys:
        if not args.recipient_id or not args.sender_id:
            parser.error('--gen-keys requires --recipient-id and --sender-id')
        gen_keypair_x25519(args.recipient_id, protect_password=args.protect_password)
        gen_keypair_ed25519(args.sender_id, protect_password=args.protect_password)
        return

    if args.mode == 'encrypt':
        if not args.infile or not args.recipient or not args.sender:
            parser.error('encrypt requires --infile --recipient (recipient X25519 pub) --sender (sender Ed25519 priv)')
        plaintext = open(args.infile, 'rb').read()
        recipient_pub = load_x25519_public(args.recipient)
        sender_priv = load_ed25519_private(args.sender, password=args.password)
        payload = encrypt(plaintext, recipient_pub, sender_priv)
        out_json = json.dumps(payload)
        if args.outfile:
            open(args.outfile, 'w').write(out_json)
            print(f'Wrote encrypted JSON to {args.outfile}')
        else:
            print(out_json)

    elif args.mode == 'decrypt':
        if not args.infile or not args.recipient or not args.sender:
            parser.error('decrypt requires --infile --recipient (recipient X25519 priv) --sender (sender Ed25519 pub)')
        payload = json.load(open(args.infile, 'r'))
        recipient_priv = load_x25519_private(args.recipient, password=args.password)
        sender_pub = load_ed25519_public(args.sender)
        plaintext = decrypt(payload, recipient_priv, sender_pub)
        if args.outfile:
            open(args.outfile, 'wb').write(plaintext)
            print(f'Wrote plaintext to {args.outfile}')
        else:
            print(plaintext.decode('utf-8', errors='replace'))

    else:
        parser.print_help()

if __name__ == '__main__':
    main(
