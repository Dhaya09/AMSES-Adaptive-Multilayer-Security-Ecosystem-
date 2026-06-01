"""
AMSES - Adaptive Encryption Engine
encryption_engine.py

Selects and applies the appropriate encryption scheme based on the
current risk level reported by the Risk Engine:

  LOW    → AES-128-CBC
  MEDIUM → AES-256-CBC
  HIGH   → AES-256-CBC + RSA-2048 Hybrid (simulated prototype)

The RSA "hybrid" layer wraps the AES session key with RSA encryption,
mirroring real-world hybrid encryption (e.g., TLS key encapsulation).
"""

import os
import base64
import json
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

# ─── RSA key pair (generated once at module load) ────────────────────────────
_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_public_key  = _rsa_private_key.public_key()

# Expose public key PEM for display
RSA_PUBLIC_PEM = _rsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()


def _aes_encrypt(plaintext: str, key_bytes: bytes) -> dict:
    iv = os.urandom(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "iv":         base64.b64encode(iv).decode(),
    }


def _aes_decrypt(ciphertext_b64: str, iv_b64: str, key_bytes: bytes) -> str:
    ct = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


def encrypt_data(plaintext: str, risk_level: str) -> dict:
    """
    Encrypt `plaintext` using the scheme appropriate for `risk_level`.
    Returns a dict with all metadata needed for the dashboard display.
    """
    risk_level = risk_level.upper()

    if risk_level == "LOW":
        # AES-128
        session_key = os.urandom(16)   # 128-bit
        result = _aes_encrypt(plaintext, session_key)
        return {
            "mode":           "AES-128-CBC",
            "risk_level":     "LOW",
            "session_key_b64": base64.b64encode(session_key).decode(),
            "key_bits":       128,
            **result,
            "rsa_wrapped_key": None,
            "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    elif risk_level == "MEDIUM":
        # AES-256
        session_key = os.urandom(32)   # 256-bit
        result = _aes_encrypt(plaintext, session_key)
        return {
            "mode":           "AES-256-CBC",
            "risk_level":     "MEDIUM",
            "session_key_b64": base64.b64encode(session_key).decode(),
            "key_bits":       256,
            **result,
            "rsa_wrapped_key": None,
            "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    else:
        # AES-256 + RSA-2048 Hybrid
        session_key = os.urandom(32)
        result = _aes_encrypt(plaintext, session_key)

        # Wrap AES session key with RSA public key
        wrapped_key = _rsa_public_key.encrypt(
            session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        return {
            "mode":            "AES-256-CBC + RSA-2048 Hybrid",
            "risk_level":      "HIGH",
            "session_key_b64": base64.b64encode(session_key).decode(),
            "key_bits":        256,
            **result,
            "rsa_wrapped_key": base64.b64encode(wrapped_key).decode(),
            "timestamp":       time.strftime("%Y-%m-%d %H:%M:%S"),
        }


def decrypt_data(payload: dict) -> str:
    """
    Decrypt a payload produced by encrypt_data().
    For HIGH risk, unwraps RSA first.
    """
    mode = payload.get("mode", "AES-128-CBC")
    iv_b64  = payload["iv"]
    ct_b64  = payload["ciphertext"]

    if "RSA" in mode and payload.get("rsa_wrapped_key"):
        wrapped = base64.b64decode(payload["rsa_wrapped_key"])
        session_key = _rsa_private_key.decrypt(
            wrapped,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    else:
        session_key = base64.b64decode(payload["session_key_b64"])

    return _aes_decrypt(ct_b64, iv_b64, session_key)


def get_rsa_public_key() -> str:
    return RSA_PUBLIC_PEM