"""
AMSES - Shared Utilities
utils.py
"""

import re
import html


def get_client_ip() -> str:
    """Get real client IP, respecting X-Forwarded-For if present."""
    from flask import request
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def sanitize_input(value: str) -> tuple[str, bool]:
    """
    Basic input sanitization.
    Returns (sanitized_value, is_suspicious).
    Detects common injection patterns.
    """
    suspicious_patterns = [
        r"[<>\"'`;]",          # XSS basics
        r"(--|;|/\*|\*/)",     # SQL comment markers
        r"(select|insert|update|delete|drop|union|exec|script)",  # SQLi / command
        r"(\.\./|%2e%2e)",     # path traversal
    ]
    sanitized = html.escape(value)
    is_suspicious = any(
        re.search(p, value, re.IGNORECASE) for p in suspicious_patterns
    )
    return sanitized, is_suspicious


def validate_login_input(username: str, password: str) -> tuple[bool, str]:
    """Validate login form inputs. Returns (valid, error_message)."""
    if not username or not password:
        return False, "Username and password are required."
    if len(username) > 64 or len(password) > 128:
        return False, "Input too long."
    _, u_suspicious = sanitize_input(username)
    _, p_suspicious = sanitize_input(password)
    if u_suspicious or p_suspicious:
        return False, "Invalid characters detected in input."
    return True, ""


def risk_color(level: str) -> str:
    return {"LOW": "#00ff9d", "MEDIUM": "#ffaa00", "HIGH": "#ff3b3b"}.get(level, "#888")


def risk_badge(level: str) -> str:
    colors = {"LOW": "badge-low", "MEDIUM": "badge-medium", "HIGH": "badge-high"}
    return colors.get(level, "badge-low")