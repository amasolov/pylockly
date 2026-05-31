"""Cryptographic primitives for the Lockly API.

Ported from the Dart lockly_api client (hacker1024/lockly_api).

Two encryption layers:
  - Anonymous (RSA): used for pre-login requests and decrypting the user key.
  - User (3DES): used for post-login requests and decrypting lock data.
"""

from __future__ import annotations

import hashlib
import math

from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

from .const import RSA_PRIVATE_KEY_DER, RSA_PUBLIC_KEY_DER

_RSA_ENCRYPT_CHUNK = 64
_RSA_DECRYPT_CHUNK = 128


def hash_password(password: str) -> str:
    """SHA-256 hex digest of the password (lowercase)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# RSA (anonymous encryption)
# ---------------------------------------------------------------------------

def _get_rsa_public_key() -> RSA.RsaKey:
    return RSA.import_key(RSA_PUBLIC_KEY_DER)


def _get_rsa_private_key() -> RSA.RsaKey:
    return RSA.import_key(RSA_PRIVATE_KEY_DER)


def _rsa_raw_encrypt(key: RSA.RsaKey, block: bytes) -> bytes:
    """Raw RSA encryption (no padding), matching the Dart PointyCastle RSAEngine."""
    plaintext_int = int.from_bytes(block, byteorder="big")
    cipher_int = pow(plaintext_int, key.e, key.n)
    return cipher_int.to_bytes(math.ceil(key.size_in_bits() / 8), byteorder="big")


def _rsa_raw_decrypt(key: RSA.RsaKey, block: bytes) -> bytes:
    """Raw RSA decryption (no padding), matching the Dart PointyCastle RSAEngine."""
    cipher_int = int.from_bytes(block, byteorder="big")
    plain_int = pow(cipher_int, key.d, key.n)
    byte_len = (plain_int.bit_length() + 7) // 8
    return plain_int.to_bytes(byte_len, byteorder="big")


def encrypt_anonymous(data: bytes) -> bytes:
    """RSA-encrypt data in 64-byte chunks using the hardcoded public key."""
    key = _get_rsa_public_key()
    num_chunks = math.ceil(len(data) / _RSA_ENCRYPT_CHUNK)
    output = bytearray()
    for i in range(num_chunks):
        start = i * _RSA_ENCRYPT_CHUNK
        end = min(start + _RSA_ENCRYPT_CHUNK, len(data))
        chunk = data[start:end]
        output.extend(_rsa_raw_encrypt(key, chunk))
    return bytes(output)


def decrypt_anonymous(data: bytes) -> bytes:
    """RSA-decrypt data in 128-byte chunks using the hardcoded private key."""
    key = _get_rsa_private_key()
    num_chunks = len(data) // _RSA_DECRYPT_CHUNK
    output = bytearray()
    for i in range(num_chunks):
        start = i * _RSA_DECRYPT_CHUNK
        chunk = data[start : start + _RSA_DECRYPT_CHUNK]
        output.extend(_rsa_raw_decrypt(key, chunk))
    return bytes(output)


# ---------------------------------------------------------------------------
# 3DES (user encryption)
# ---------------------------------------------------------------------------

def encrypt_user(key: bytes, data: bytes) -> bytes:
    """3DES-ECB encrypt with PKCS7 padding."""
    adjusted_key = DES3.adjust_key_parity(key[:24])
    cipher = DES3.new(adjusted_key, DES3.MODE_ECB)
    return cipher.encrypt(pad(data, DES3.block_size))


def decrypt_user(key: bytes, data: bytes) -> bytes:
    """3DES-ECB decrypt with PKCS7 unpadding."""
    adjusted_key = DES3.adjust_key_parity(key[:24])
    cipher = DES3.new(adjusted_key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(data), DES3.block_size)
