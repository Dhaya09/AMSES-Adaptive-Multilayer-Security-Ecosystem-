"""
AMSES - Flask Routes
routes.py

All application endpoints wired together:
  - Page routes (HTML)
  - Auth API
  - Secure data API
  - Dashboard API
  - Admin / control API
"""

import json
import time
from flask import (
    Blueprint, render_template, request, jsonify,
    redirect, url_for, make_response
)
from app import limiter
from app.auth import (
    verify_password, generate_token, decode_token,
    require_auth, adaptive_auth_challenge
)
from app.risk_engine import (
    record_event, get_risk_profile, get_risk_score,
    get_risk_level, encryption_for_level, get_global_events
)
from app.firewall import block_ip, is_blocked, get_blocked_ips, unblock_ip
from app.detector import observe_request, record_failed_login, reset_failed_logins, get_failed_logins
from app.encryption_engine import encrypt_data, decrypt_data, get_rsa_public_key
from app.alerts import raise_alert, log_auth, log_risk, log_blocked, get_all_logs, get_recent_alerts
from app.dashboard import get_dashboard_data
from app.utils import get_client_ip, validate_login_input, sanitize_input
import config

bp = Blueprint("main", __name__)


# ─── Middleware helpers ───────────────────────────────────────────────────────

def _firewall_check(ip: str) -> bool:
    """Return True if IP is currently blocked."""
    return is_blocked(ip)


def _observe_and_score(ip: str, signal: str = None, detail: str = "") -> dict:
    """Run detector + optionally record a risk signal, return risk profile."""
    detection = observe_request(ip)
    if detection["flood_detected"]:
        profile = record_event(ip, "flood_request", f"rate={detection['request_rate']}/10s")
        log_risk(ip, profile["score"], profile["level"], "flood_request")
        if profile["level"] == "HIGH":
            _auto_block(ip, "Request flood detected")
    if signal:
        profile = record_event(ip, signal, detail)
        log_risk(ip, profile["score"], profile["level"], signal)
        if profile["level"] == "HIGH":
            _auto_block(ip, f"High risk: {signal}")
    return get_risk_profile(ip)


def _auto_block(ip: str, reason: str) -> None:
    if not is_blocked(ip):
        block_ip(ip, reason=reason)
        log_blocked(ip, reason)
        raise_alert(ip, "AUTO_BLOCK", reason, "HIGH")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/")
def index():
    ip = get_client_ip()
    if _firewall_check(ip):
        return render_template("blocked.html", ip=ip), 403
    return render_template("index.html")


@bp.route("/login")
def login_page():
    ip = get_client_ip()
    if _firewall_check(ip):
        return render_template("blocked.html", ip=ip), 403
    failed = get_failed_logins(ip)
    challenge = adaptive_auth_challenge(failed)
    return render_template("login.html", challenge=challenge)


@bp.route("/secure")
def secure_page():
    ip = get_client_ip()
    if _firewall_check(ip):
        return render_template("blocked.html", ip=ip), 403
    token = request.cookies.get("amses_token")
    if not token:
        return redirect(url_for("main.login_page"))
    payload = decode_token(token)
    if payload is None:
        return redirect(url_for("main.login_page"))
    risk_level = get_risk_level(ip)
    enc_mode   = encryption_for_level(risk_level)
    score      = get_risk_score(ip)
    return render_template("secure.html",
                           username=payload["sub"],
                           risk_level=risk_level,
                           enc_mode=enc_mode,
                           score=score)


@bp.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@bp.route("/logout")
def logout():
    resp = make_response(redirect(url_for("main.index")))
    resp.delete_cookie("amses_token")
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# AUTH API
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/api/login", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_LOGIN)
def api_login():
    ip = get_client_ip()

    if _firewall_check(ip):
        return jsonify({"success": False, "error": "IP is blocked by AMSES Firewall"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # Input validation
    valid, err = validate_login_input(username, password)
    if not valid:
        _observe_and_score(ip, "invalid_input", err)
        return jsonify({"success": False, "error": err}), 400

    # Verify credentials
    if not verify_password(username, password):
        count = record_failed_login(ip)
        profile = _observe_and_score(ip, "failed_login", f"user={username} attempt={count}")
        log_auth(ip, username, False, f"attempt {count}")
        raise_alert(ip, "FAILED_LOGIN", f"attempt {count} for user={username}", profile["level"])

        challenge = adaptive_auth_challenge(count)
        if profile["level"] == "HIGH" or count >= config.MAX_FAILED_LOGINS_BEFORE_BLOCK:
            _auto_block(ip, f"Brute-force: {count} failed logins")
            return jsonify({
                "success": False,
                "error":   "Too many failed attempts. IP blocked.",
                "blocked": True,
                "challenge": challenge,
            }), 429

        return jsonify({
            "success":   False,
            "error":     "Invalid credentials.",
            "attempts":  count,
            "challenge": challenge,
            "risk":      profile["score"],
        }), 401

    # Successful login
    reset_failed_logins(ip)
    profile = _observe_and_score(ip)
    token = generate_token(username, ip, profile["level"])
    log_auth(ip, username, True)

    resp = make_response(jsonify({
        "success":    True,
        "token":      token,
        "risk_level": profile["level"],
        "enc_mode":   profile["encryption_mode"],
        "score":      profile["score"],
    }))
    resp.set_cookie("amses_token", token, httponly=True, samesite="Strict", max_age=3600)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# SECURE DATA API
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/api/secure-data")
@require_auth
def api_secure_data():
    ip = get_client_ip()
    if _firewall_check(ip):
        return jsonify({"error": "IP blocked"}), 403

    profile = _observe_and_score(ip)
    risk_level = profile["level"]

    # The "sensitive data" being protected
    sensitive_payload = json.dumps({
        "message":     "AMSES CLASSIFIED PAYLOAD",
        "user":        request.jwt_payload["sub"],
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "clearance":   "LEVEL-3",
        "data_id":     "DS-20250001",
    })

    encrypted = encrypt_data(sensitive_payload, risk_level)
    # Also return decrypted for demo display
    decrypted = decrypt_data(encrypted)

    return jsonify({
        "success":        True,
        "risk_profile":   profile,
        "encrypted":      encrypted,
        "decrypted_demo": json.loads(decrypted),
        "rsa_public_key": get_rsa_public_key() if risk_level == "HIGH" else None,
    })


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD API
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/api/dashboard")
def api_dashboard():
    return jsonify(get_dashboard_data())


@bp.route("/api/logs")
def api_logs():
    return jsonify(get_all_logs())


@bp.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts())


@bp.route("/api/events")
def api_events():
    return jsonify(get_global_events(50))


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK SIMULATION INTAKE (called by simulation scripts)
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/api/sim/trigger", methods=["POST"])
def api_sim_trigger():
    """Internal endpoint used by attack simulation scripts."""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", get_client_ip())
    sig  = data.get("signal", "attack_simulation")
    det  = data.get("detail", "simulation")
    profile = record_event(ip, sig, det)
    log_risk(ip, profile["score"], profile["level"], sig)
    raise_alert(ip, "ATTACK_SIMULATION", det, profile["level"])
    if profile["level"] == "HIGH":
        _auto_block(ip, f"Attack simulation triggered high risk: {det}")
    return jsonify({"success": True, "profile": profile})


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN CONTROLS
# ══════════════════════════════════════════════════════════════════════════════

@bp.route("/api/admin/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if unblock_ip(ip):
        return jsonify({"success": True, "message": f"{ip} unblocked"})
    return jsonify({"success": False, "message": "IP not found in blocklist"})


@bp.route("/api/admin/blocked-ips")
def api_blocked_ips():
    return jsonify(get_blocked_ips())


# ══════════════════════════════════════════════════════════════════════════════
# CATCH-ALL FOR BLOCKED IPs ON ANY ROUTE
# ══════════════════════════════════════════════════════════════════════════════

@bp.before_request
def global_firewall():
    ip = get_client_ip()
    if request.path.startswith("/static"):
        return
    if is_blocked(ip) and request.path not in ("/", "/login"):
        # Let index/login show the blocked page gracefully
        if request.path.startswith("/api"):
            return jsonify({"error": "IP blocked by AMSES Firewall", "ip": ip}), 403