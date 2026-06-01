"""
AMSES - Adaptive Multilayer Security Ecosystem with Alert Systems
config.py - Central configuration file
"""

import os
import secrets

# ─── Flask ───────────────────────────────────────────────────────────────────
SECRET_KEY = secrets.token_hex(32)
DEBUG = True
HOST = "127.0.0.1"
PORT = 5000

# ─── Demo credentials (hardcoded, no DB) ─────────────────────────────────────
DEMO_USERNAME = "admin"
DEMO_PASSWORD = "SecurePass@123"   # plain-text used ONLY to generate hash at startup

# ─── JWT ─────────────────────────────────────────────────────────────────────
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600          # 1 hour

# ─── Risk thresholds ─────────────────────────────────────────────────────────
RISK_LOW_MAX    = 33
RISK_MEDIUM_MAX = 66
# > 66 → HIGH

# ─── Scoring weights ─────────────────────────────────────────────────────────
SCORE_FAILED_LOGIN          = 15
SCORE_BLOCKED_ATTEMPT       = 25
SCORE_INVALID_INPUT         = 10
SCORE_SUSPICIOUS_REQUEST    = 8
SCORE_UNAUTHORIZED_ACCESS   = 20
SCORE_FLOOD_REQUEST         = 12
SCORE_ATTACK_SIM            = 30
SCORE_DECAY_PER_SECOND      = 0.05  # passive score decay rate

# ─── Auto-block thresholds ───────────────────────────────────────────────────
MAX_FAILED_LOGINS_BEFORE_BLOCK = 5
BLOCK_DURATION_SECONDS         = 120   # 2 minutes

# ─── Encryption ──────────────────────────────────────────────────────────────
ENCRYPTION_LOW    = "AES-128-CBC"
ENCRYPTION_MEDIUM = "AES-256-CBC"
ENCRYPTION_HIGH   = "AES-256-CBC + RSA-2048 Hybrid"

# ─── Rate limiting ────────────────────────────────────────────────────────────
RATE_LIMIT_LOGIN  = "20 per minute"
RATE_LIMIT_API    = "60 per minute"

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_DIR      = os.path.join(os.path.dirname(__file__), "logs")
LOG_AUTH     = os.path.join(LOG_DIR, "auth.log")
LOG_RISK     = os.path.join(LOG_DIR, "risk.log")
LOG_ALERTS   = os.path.join(LOG_DIR, "alerts.log")
LOG_BLOCKED  = os.path.join(LOG_DIR, "blocked_ips.log")
LOG_EVENTS   = os.path.join(LOG_DIR, "events.log")

# ─── Alerting (SMTP - set to None to use simulated alerts only) ──────────────
SMTP_ENABLED  = False
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USER     = ""
SMTP_PASS     = ""
ALERT_EMAIL   = ""