"""
AMSES - Firewall / Automated Response Module
firewall.py

Maintains an in-memory IP blocklist with TTL-based expiry.
Acts as the automated defense layer: when risk reaches HIGH,
the risk engine triggers block_ip() here, denying further access.

Architecture note: in a production deployment this layer would
interface with iptables/nftables or a cloud WAF API.
"""

import time
import threading
from config import BLOCK_DURATION_SECONDS

_lock = threading.RLock()

# { ip: unblock_timestamp }
_blocked_ips: dict = {}

# Permanent block log (never expires from log, only from active block)
_block_history: list = []


def block_ip(ip: str, reason: str = "Automated: High Risk Score",
             duration: int = BLOCK_DURATION_SECONDS) -> None:
    """Block an IP for `duration` seconds."""
    with _lock:
        unblock_at = time.time() + duration
        _blocked_ips[ip] = unblock_at
        entry = {
            "ip": ip,
            "reason": reason,
            "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
            "unblock_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(unblock_at)),
        }
        _block_history.insert(0, entry)
        _block_history[:] = _block_history[:100]


def unblock_ip(ip: str) -> bool:
    with _lock:
        if ip in _blocked_ips:
            del _blocked_ips[ip]
            return True
        return False


def is_blocked(ip: str) -> bool:
    with _lock:
        if ip not in _blocked_ips:
            return False
        if time.time() >= _blocked_ips[ip]:
            del _blocked_ips[ip]   # TTL expired → auto-unblock
            return False
        return True


def get_blocked_ips() -> list:
    """Return currently active blocked IPs with remaining seconds."""
    with _lock:
        now = time.time()
        active = []
        expired = []
        for ip, unblock_at in _blocked_ips.items():
            if now >= unblock_at:
                expired.append(ip)
            else:
                active.append({
                    "ip": ip,
                    "remaining_seconds": int(unblock_at - now),
                    "unblock_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(unblock_at)),
                })
        for ip in expired:
            del _blocked_ips[ip]
        return active


def get_block_history(limit: int = 30) -> list:
    with _lock:
        return _block_history[:limit]


def get_blocked_count() -> int:
    return len(get_blocked_ips())