"""
AMSES - Detection / Threat Observation Module
detector.py

Lightweight rule-based IDS layer that observes incoming requests,
identifies suspicious behavioral patterns, and feeds signals to
the Risk Engine.

Architecture note: This module is intentionally structured to support
future AI-assisted intrusion detection:
  - Each detection rule can be replaced by an ML decision boundary.
  - The _request_log per IP can feed a sequence model (LSTM / Transformer)
    for temporal anomaly detection.
  - Isolation Forest or One-Class SVM could replace the threshold rules
    for unsupervised anomaly scoring.
"""

import time
import threading
from collections import defaultdict

_lock = threading.RLock()

# { ip: [timestamp, ...] }  – sliding window of request timestamps
_request_log: dict = defaultdict(list)

# { ip: failed_login_count }
_failed_logins: dict = defaultdict(int)

# Configurable thresholds
FLOOD_WINDOW_SECONDS  = 10
FLOOD_REQUEST_LIMIT   = 30    # >30 requests in 10 s = flood
BRUTEFORCE_LIMIT      = 5     # >5 failed logins = brute-force flag


def observe_request(ip: str) -> dict:
    """
    Called on every incoming request.
    Returns detection flags for this IP.
    """
    with _lock:
        now = time.time()
        window_start = now - FLOOD_WINDOW_SECONDS
        _request_log[ip].append(now)
        # Trim old timestamps outside window
        _request_log[ip] = [t for t in _request_log[ip] if t >= window_start]
        count = len(_request_log[ip])

        return {
            "flood_detected":      count > FLOOD_REQUEST_LIMIT,
            "request_rate":        count,
            "brute_force_suspect": _failed_logins[ip] >= BRUTEFORCE_LIMIT,
            "failed_login_count":  _failed_logins[ip],
        }


def record_failed_login(ip: str) -> int:
    """Increment failed login counter for IP, return new count."""
    with _lock:
        _failed_logins[ip] += 1
        return _failed_logins[ip]


def reset_failed_logins(ip: str) -> None:
    with _lock:
        _failed_logins[ip] = 0


def get_failed_logins(ip: str) -> int:
    with _lock:
        return _failed_logins[ip]


def get_all_stats() -> list:
    with _lock:
        now = time.time()
        window_start = now - FLOOD_WINDOW_SECONDS
        stats = []
        all_ips = set(list(_request_log.keys()) + list(_failed_logins.keys()))
        for ip in all_ips:
            recent = [t for t in _request_log.get(ip, []) if t >= window_start]
            stats.append({
                "ip":                  ip,
                "request_rate_10s":    len(recent),
                "failed_logins":       _failed_logins.get(ip, 0),
                "brute_force_suspect": _failed_logins.get(ip, 0) >= BRUTEFORCE_LIMIT,
                "flood_suspect":       len(recent) > FLOOD_REQUEST_LIMIT,
            })
        return sorted(stats, key=lambda x: x["failed_logins"], reverse=True)