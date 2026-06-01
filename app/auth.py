"""
AMSES - Authentication Module
auth.py

Handles:
  - bcrypt password hashing
  - JWT token issuance / validation
  - Adaptive authentication escalation hooks
"""

import time
import bcrypt
import jwt
from functools import wraps
from flask import request, jsonify
from config import (
    DEMO_USERNAME, DEMO_PASSWORD,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_SECONDS
)

# ─── Hash demo password at startup ───────────────────────────────────────────
_DEMO_HASH: bytes = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt())

# In-memory "user store" (no DB)
USERS = {
    DEMO_USERNAME: _DEMO_HASH,
}


def verify_password(username: str, password: str) -> bool:
    """Return True if username and password match the demo credentials."""
    stored_hash = USERS.get(username)
    if stored_hash is None:
        return False
    return bcrypt.checkpw(password.encode(), stored_hash)


def generate_token(username: str, ip: str, risk_level: str) -> str:
    """Issue a signed JWT embedding username, IP, and current risk level."""
    payload = {
        "sub":        username,
        "ip":         ip,
        "risk_level": risk_level,
        "iat":        int(time.time()),
        "exp":        int(time.time()) + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT. Returns payload dict or None."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_from_request() -> str | None:
    """Extract token from Authorization header or cookie."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Also accept from cookie (for browser navigation)
    return request.cookies.get("amses_token")


def require_auth(f):
    """Decorator: protect routes that require a valid JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({"error": "Authentication required", "code": 401}), 401
        payload = decode_token(token)
        if payload is None:
            return jsonify({"error": "Invalid or expired token", "code": 401}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated


def adaptive_auth_challenge(failed_count: int) -> dict:
    """
    Prototype adaptive authentication escalation.
    Returns the challenge level based on prior failures.

    Future extension: integrate CAPTCHA, OTP, or step-up MFA.
    """
    if failed_count < 3:
        return {"level": "standard", "message": "Password required"}
    elif failed_count < 6:
        return {"level": "elevated", "message": "Password required. Account under observation."}
    else:
        return {"level": "blocked",  "message": "Too many failures. Account temporarily locked."}