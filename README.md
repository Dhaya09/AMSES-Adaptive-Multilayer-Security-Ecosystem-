# AMSES — Adaptive Multilayer Security Ecosystem with Alert Systems

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1.3-000000?style=for-the-badge&logo=flask&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-Auth-purple?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![AES](https://img.shields.io/badge/AES--256--CBC-Encryption-green?style=for-the-badge)
![RSA](https://img.shields.io/badge/RSA--2048-Hybrid-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

---

## Overview

**AMSES** (Adaptive Multilayer Security Ecosystem with Alert Systems) is a real-time cybersecurity web application that simulates and demonstrates a full-stack adaptive defense system. Built with Flask, AMSES integrates multiple security layers — threat detection, dynamic risk scoring, adaptive encryption, automated IP blocking, and live alerting — all visible through a real-time security dashboard.

The system continuously monitors incoming requests per IP, evaluates behavioral signals (brute-force attempts, request floods, injection inputs, unauthorized access), computes a dynamic 0–100 risk score, and autonomously escalates its defenses in response — from changing encryption strength to blocking the offending IP entirely.

AMSES is designed as both a working security prototype and an educational cybersecurity demonstration platform, complete with attack simulation scripts that let you observe the system's response in real time.

---

## Features

- **Adaptive Risk Scoring Engine** — Each IP is assigned a live 0–100 risk score calculated from weighted behavioral signals. The score decays passively over time but is pinned at a minimum of 85 for actively blocked IPs to ensure dashboard accuracy.

- **Three-Level Threat Classification** — Risk is categorized as LOW (0–33), MEDIUM (34–66), or HIGH (67–100), with each level triggering proportionate automated responses.

- **Adaptive Encryption Engine** — Encryption strength escalates with risk level:
  - LOW → AES-128-CBC
  - MEDIUM → AES-256-CBC
  - HIGH → AES-256-CBC + RSA-2048 Hybrid (AES session key wrapped with RSA public key)

- **Rule-Based IDS Layer** — Detects request floods (>30 requests in 10 seconds), brute-force login attempts (>5 failed logins), suspicious user inputs, and unauthorized endpoint access.

- **Automated IP Firewall** — IPs that reach HIGH risk are automatically blocked for a configurable TTL (default: 2 minutes) with full block history logging.

- **JWT Authentication** — Stateless JSON Web Token auth with bcrypt password hashing. Tokens embed IP, username, risk level, and a 1-hour expiry.

- **Adaptive Authentication Escalation** — Login challenge level escalates with prior failure count: standard → elevated (account under observation) → blocked (temporarily locked).

- **Live Security Dashboard** — Real-time dashboard (polling every 3 seconds) showing risk gauge, active blocked IPs, per-IP event history, encryption mode, and system-wide alerts.

- **Structured Multi-Log System** — Five independent log streams: `auth.log`, `risk.log`, `alerts.log`, `blocked_ips.log`, `events.log`.

- **SMTP Alert System** — Optional email alerting on high-risk events (configurable; simulated by default).

- **Input Sanitization & Injection Detection** — Every login input is scanned for XSS patterns, SQL injection markers, command injection, and path traversal sequences.

- **Attack Simulation Scripts** — Three built-in educational attack scripts:
  - `brute_force.py` — simulates repeated credential stuffing
  - `request_flood.py` — simulates a DoS-style request flood
  - `suspicious_access.py` — simulates unauthorized access and injection attempts

- **Rate Limiting** — Flask-Limiter enforces 20 requests/minute on login and 60 requests/minute on the API globally.

---

## Screenshots / Demo

> Run the application locally and navigate to `http://127.0.0.1:5000/dashboard` to see the live dashboard.

**Dashboard panels include:**
- System Risk Gauge (color-coded bar: green → amber → red)
- MAX RISK SCORE, ENCRYPTION MODE, BLOCKED IPs, THREAT IPs metrics
- Per-IP risk table with scores and event counts
- Real-time event feed and alert log
- Active blocked IPs with TTL countdown
- Detector stats (flood suspect, brute-force suspect flags)

**Sample event log output (from actual run):**
```
[2026-04-04 08:41:44] RISK LOW     | IP=127.0.0.1 | score=15.0
[2026-04-04 08:42:37] RISK MEDIUM  | IP=127.0.0.1 | score=57.3
[2026-04-04 08:42:38] RISK HIGH    | IP=127.0.0.1 | score=72.3
[2026-04-04 08:42:38] BLOCKED      | IP=127.0.0.1
```

---

## Architecture

```
+----------------------------------------------------------------------+
|                         AMSES Architecture                           |
+----------------------------------------------------------------------+
|                                                                      |
|   Browser / Attack Scripts                                           |
|          |                                                           |
|          v                                                           |
|   +-----------------+                                                |
|   |  Flask Routes   |  <- global_firewall() before_request hook     |
|   |  (routes.py)    |                                                |
|   +--------+--------+                                                |
|            |                                                         |
|     +------+---------------------------+                             |
|     v      v              v            v                             |
|  +------+ +--------+ +----------+ +----------+                      |
|  | IDS  | |  Auth  | |   Risk   | | Firewall |                      |
|  | Layer| | Module | |  Engine  | |  Module  |                      |
|  +--+---+ +---+----+ +----+-----+ +----+-----+                      |
|     |         |           |            |                             |
|     +----+----+           |            |                             |
|          v                v            v                             |
|   +-------------+  +-------------+ +--------------+                 |
|   | Encryption  |  |  Alerting   | |  Dashboard   |                 |
|   |   Engine    |  |  & Logging  | |  Aggregator  |                 |
|   +-------------+  +-------------+ +--------------+                 |
|                                                                      |
|  Signal flow:                                                        |
|  Request -> IDS observe -> Risk score -> Firewall check              |
|          -> Encryption escalate -> Alert/Log -> Dashboard update     |
+----------------------------------------------------------------------+
```

Every incoming request passes through a `before_request` global firewall hook. Blocked IPs are rejected at the gate. All others flow through the IDS detector, which feeds behavioral signals into the Risk Engine. The Risk Engine maintains per-IP state with passive decay and drives both the Firewall (auto-block on HIGH) and the Encryption Engine (mode selection). All events are persisted across five structured log files and surfaced on the live dashboard.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web Framework | Flask 3.1.3 |
| Authentication | Flask-JWT-Extended 4.7.1, PyJWT 2.12.1 |
| Password Hashing | bcrypt 5.0.0 |
| Symmetric Encryption | PyCryptodome 3.23.0 (AES-128/256-CBC) |
| Asymmetric Encryption | cryptography 46.0.6 (RSA-2048, OAEP/SHA-256) |
| Rate Limiting | Flask-Limiter 4.1.1 |
| Templating | Jinja2 3.1.6 |
| Frontend | Vanilla JS, CSS3 (Share Tech Mono + Rajdhani fonts) |
| Alerting | SMTP via smtplib (simulated by default) |
| Runtime | Python 3.11+ |

---

## Folder Structure

```
AMSES/
├── run.py                        # Application entry point
├── config.py                     # Central configuration (keys, thresholds, weights)
├── requirements.txt              # Python dependencies
│
├── app/
│   ├── __init__.py               # Flask app factory + Limiter setup
│   ├── routes.py                 # All HTTP endpoints (pages + API)
│   ├── auth.py                   # JWT issuance, bcrypt verification, adaptive auth
│   ├── detector.py               # IDS layer: flood detection, brute-force tracking
│   ├── risk_engine.py            # Core risk scoring, decay, classification
│   ├── firewall.py               # IP blocklist with TTL-based auto-expiry
│   ├── encryption_engine.py      # AES-128/256 + RSA-2048 hybrid encryption
│   ├── alerts.py                 # Structured logging + SMTP alert dispatch
│   ├── dashboard.py              # Dashboard data aggregator
│   └── utils.py                  # Input sanitization, IP extraction, helpers
│
├── templates/
│   ├── index.html                # Landing page
│   ├── login.html                # Login portal with adaptive challenge display
│   ├── secure.html               # Authenticated secure data view
│   ├── dashboard.html            # Live security monitoring dashboard
│   └── blocked.html              # Blocked IP access denial page
│
├── static/
│   ├── style.css                 # Global dark-theme cybersecurity UI styles
│   └── script.js                 # Dashboard polling, chart updates, UI logic
│
├── logs/
│   ├── auth.log                  # Authentication success/failure records
│   ├── risk.log                  # Risk score changes with trigger context
│   ├── alerts.log                # High-risk alert events
│   ├── blocked_ips.log           # IP block records
│   └── events.log                # Unified event timeline
│
└── attacks/
    ├── brute_force.py            # Simulates credential stuffing attack
    ├── request_flood.py          # Simulates DoS-style request flood
    └── suspicious_access.py      # Simulates injection + unauthorized access
```

---

## Installation

### Prerequisites

- Python 3.11 or higher
- pip

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/your-username/amses.git
cd amses
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the application**
```bash
python run.py
```

The server starts at `http://127.0.0.1:5000`. Log files are created automatically in the `logs/` directory on first run.

---

## Configuration

All tuneable parameters live in `config.py`. No `.env` file is required for local use.

| Parameter | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `5000` | Server port |
| `DEMO_USERNAME` | `admin` | Demo login username |
| `DEMO_PASSWORD` | `SecurePass@123` | Demo login password |
| `JWT_EXPIRY_SECONDS` | `3600` | JWT token lifetime (1 hour) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `RISK_LOW_MAX` | `33` | Upper bound for LOW risk |
| `RISK_MEDIUM_MAX` | `66` | Upper bound for MEDIUM risk |
| `SCORE_FAILED_LOGIN` | `15` | Risk points per failed login |
| `SCORE_BLOCKED_ATTEMPT` | `25` | Risk points for blocked IP attempt |
| `SCORE_FLOOD_REQUEST` | `12` | Risk points for flood signal |
| `SCORE_ATTACK_SIM` | `30` | Risk points for simulation trigger |
| `SCORE_DECAY_PER_SECOND` | `0.05` | Passive risk score decay rate |
| `MAX_FAILED_LOGINS_BEFORE_BLOCK` | `5` | Failed logins triggering auto-block |
| `BLOCK_DURATION_SECONDS` | `120` | IP block TTL (2 minutes) |
| `RATE_LIMIT_LOGIN` | `20 per minute` | Login endpoint rate cap |
| `RATE_LIMIT_API` | `60 per minute` | API endpoint rate cap |
| `SMTP_ENABLED` | `False` | Enable real email alerts |

To enable SMTP email alerts, set `SMTP_ENABLED = True` and fill in `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `ALERT_EMAIL` in `config.py`.

---

## Usage

### Normal Flow

1. Navigate to `http://127.0.0.1:5000`
2. Go to `/login` and authenticate with:
   - **Username:** `admin`
   - **Password:** `SecurePass@123`
3. On successful login, a JWT cookie (`amses_token`) is set and you are redirected to `/secure`
4. The `/secure` page displays your current risk level and active encryption mode
5. Open `/dashboard` in a separate tab to monitor the system in real time

### Running Attack Simulations

All scripts target localhost only and are for educational/demonstration purposes.

**Brute Force Simulation**
```bash
python attacks/brute_force.py
```
Sends 15 wrong-password attempts. Risk score rises with each failure. After 5 failed logins the IP is auto-blocked and the dashboard reflects HIGH risk + blocked status.

**Request Flood Simulation**
```bash
python attacks/request_flood.py
```
Sends 50 rapid requests across 5 concurrent threads. Triggers the IDS flood detector when the rate exceeds 30 requests in 10 seconds, spiking the risk score.

**Suspicious Access Simulation**
```bash
python attacks/suspicious_access.py
```
Sends unauthorized requests to protected endpoints, SQL injection payloads, XSS strings, and path traversal inputs. Each triggers `invalid_input` or `unauthorized_access` risk signals.

---

## API Documentation

### Authentication

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/login` | POST | Authenticate with username/password. Returns JWT token and current risk profile. |

**Request body:**
```json
{ "username": "admin", "password": "SecurePass@123" }
```

**Response (success):**
```json
{
  "success": true,
  "token": "<JWT>",
  "risk_level": "LOW",
  "enc_mode": "AES-128-CBC",
  "score": 0.0
}
```

**Response (failure — brute-force detected):**
```json
{
  "success": false,
  "error": "Too many failed attempts. IP blocked.",
  "blocked": true,
  "challenge": { "level": "blocked", "message": "Too many failures. Account temporarily locked." }
}
```

---

### Secure Data

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `GET /api/secure-data` | GET | JWT required | Returns encrypted payload + decrypted demo. Encryption mode is risk-adaptive. |

**Response:**
```json
{
  "success": true,
  "risk_profile": { "ip": "...", "score": 12.5, "level": "LOW", "encryption_mode": "AES-128-CBC" },
  "encrypted": { "mode": "AES-128-CBC", "ciphertext": "...", "iv": "...", "key_bits": 128 },
  "decrypted_demo": { "message": "AMSES CLASSIFIED PAYLOAD", "user": "admin", "clearance": "LEVEL-3" },
  "rsa_public_key": null
}
```

---

### Dashboard & Monitoring

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/dashboard` | GET | Full system state: risk scores, blocked IPs, events, alerts, detector stats |
| `GET /api/logs` | GET | Last 50 lines from all five log files |
| `GET /api/alerts` | GET | Most recent 20 alert entries |
| `GET /api/events` | GET | Most recent 50 global security events |

---

### Admin Controls

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/admin/unblock` | POST | Manually unblock an IP |
| `GET /api/admin/blocked-ips` | GET | List all currently active blocks with TTL remaining |

**Unblock request body:**
```json
{ "ip": "127.0.0.1" }
```

---

### Attack Simulation Intake

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/sim/trigger` | POST | Inject a risk signal directly (used by attack scripts) |

**Request body:**
```json
{ "signal": "attack_simulation", "detail": "custom simulation event" }
```

Valid signal values: `failed_login`, `blocked_attempt`, `invalid_input`, `suspicious_request`, `unauthorized_access`, `flood_request`, `attack_simulation`

---

## Workflow

```
Incoming Request
      |
      v
[global_firewall] ---- IP blocked? ---- YES ---> Return 403 / blocked.html
      | NO
      v
[observe_request] ---- Flood detected? -- YES ---> record flood_request signal
      |
      v
[validate input] ---- Suspicious pattern? -- YES ---> record invalid_input signal
      |
      v
[verify_password]
  +-- FAIL ---> record_failed_login -> risk score += 15
  |             adaptive_auth_challenge (standard / elevated / blocked)
  |             count >= 5 -> _auto_block(ip)
  |
  +-- SUCCESS ---> reset_failed_logins -> generate_token -> set JWT cookie
                   redirect to /secure
      |
      v
[Risk Engine] classifies score -> LOW / MEDIUM / HIGH
      |
      +-- MEDIUM ---> Escalate to AES-256-CBC
      +-- HIGH   ---> Escalate to AES-256-CBC + RSA-2048 Hybrid
      |               _auto_block(ip) if not already blocked
      |               raise_alert(ip, event_type, detail, level)
      |
      v
[alerts.py] ---> Write to log files
             ---> SMTP email (if enabled)
             ---> Store in _alert_history (in-memory, last 50)
      |
      v
[/dashboard] polls /api/dashboard every 3s ---> Live UI update
```

---

## Security Features

**Authentication**
- Passwords are never stored in plaintext — bcrypt with random salt is generated at startup
- JWTs are signed with a per-session `secrets.token_hex(32)` secret key that rotates on every restart
- Tokens embed the issuing IP; mismatch can be detected on validation
- Tokens are set as `httponly`, `SameSite=Strict` cookies — inaccessible from JavaScript

**Input Validation**
- All login inputs are scanned for XSS basics (`<>'";\``), SQL comment markers (`-- ; /* */`), SQL keywords (`SELECT`, `DROP`, `UNION`, `EXEC`), and path traversal sequences (`../`, `%2e%2e`)
- Suspicious inputs immediately raise an `invalid_input` risk signal
- All values are HTML-escaped before any further processing

**Adaptive Encryption**
- Encryption algorithm escalates based on live risk level — not a fixed scheme
- At HIGH risk, the AES session key itself is wrapped with RSA-2048 OAEP (SHA-256), mirroring TLS key encapsulation
- RSA key pair is generated fresh at each application start

**Network Defense**
- Flask-Limiter enforces hard rate limits: 20/min on login, 60/min on the API, 200/min globally
- IPs exceeding 30 requests in any 10-second window are flagged as flood suspects
- Auto-blocking triggers on HIGH risk; blocks carry a TTL with automatic expiry
- `X-Forwarded-For` header is parsed to correctly identify real IPs behind proxies

**Logging**
- Five structured log streams, each timestamped, provide a full audit trail across auth, risk, alerts, blocks, and events

---

## Testing

Three built-in attack simulation scripts serve as functional test cases. Run them against a locally running server to verify each layer of the system responds correctly.

**Expected results:**

| Simulation | Expected System Response |
|---|---|
| `brute_force.py` | Risk rises to HIGH after 5 failures; IP auto-blocked; dashboard shows BLOCKED; encryption escalates to AES-256/Hybrid |
| `request_flood.py` | Flood detected on >30 req/10s; risk score spikes; `flood_suspect` flag appears in detector stats |
| `suspicious_access.py` | `invalid_input` + `unauthorized_access` signals raised; alerts logged; risk score increases per event |

Verify responses in real time on the dashboard at `http://127.0.0.1:5000/dashboard` or by tailing log files:

```bash
tail -f logs/events.log
```

---

## Results / Performance

From actual test runs captured in the event log:

- Risk score escalated from 0 to 72.3 across 5 failed login attempts
- AUTO_BLOCK triggered correctly at the 5th failure
- Score classification progressed cleanly: LOW (15.0) → MEDIUM (42.3 → 57.3) → HIGH (72.3)
- Blocked IPs are pinned at a minimum score of 85.0 on the dashboard for accurate threat visibility
- Passive decay rate of 0.05 points/second allows organic score recovery after threats subside
- In-memory state with `threading.RLock()` ensures thread-safe handling of concurrent requests

---

## Future Enhancements

- **ML-Based Anomaly Detection** — The detector module is architecturally ready to replace rule-based thresholds with Isolation Forest, One-Class SVM, or LSTM/Transformer sequence models. The per-IP sliding window `_request_log` is designed to feed such a model directly.

- **Multi-Factor Authentication (MFA)** — The `adaptive_auth_challenge` hook is a ready placeholder for CAPTCHA or TOTP step-up challenges at elevated risk.

- **Database-Backed User Store** — Replace the in-memory `USERS` dict with SQLAlchemy + PostgreSQL for production-grade user management.

- **Production Firewall Integration** — The firewall module is designed to interface with `iptables`/`nftables` or a cloud WAF API in place of the in-memory blocklist.

- **Persistent Risk State** — Risk scores and block history reset on server restart. Redis or a lightweight DB could persist state across sessions.

- **Role-Based Access Control (RBAC)** — Extend JWT payload with role claims and enforce per-route authorization levels.

- **Webhook / Slack Alerting** — Add webhook support alongside SMTP so alerts can route to Slack, PagerDuty, or similar platforms.

- **Dockerization** — Package the application in a container for reproducible deployment.

---

## Challenges Faced

**1. Risk Score Decay vs. Dashboard Accuracy**
The passive decay mechanism (0.05 points/second) caused blocked IPs to decay back toward 0 quickly, making them effectively invisible on the dashboard immediately after being blocked. This was resolved by pinning the minimum score to 85.0 for any IP present in the active blocklist, enforced at both the `_decay()` function and the `get_risk_profile()` retrieval level.

**2. Thread-Safe In-Memory State**
Multiple concurrent requests (especially during flood simulation) race to update the same IP's risk state. All shared state in `risk_engine.py`, `firewall.py`, and `detector.py` is protected with `threading.RLock()` to prevent race conditions.

**3. Hybrid Encryption Architecture**
Implementing a correct RSA-2048 + AES-256 hybrid scheme required careful alignment between PyCryptodome (AES layer) and the `cryptography` library (RSA layer). OAEP padding with SHA-256 was selected for its security properties over the weaker PKCS1v15 scheme.

**4. Adaptive Auth Without a Database**
Implementing login escalation (standard → elevated → blocked) with no persistent storage required stateful in-memory tracking of failed counts per IP, decoupled from the broader risk score to allow independent reset on successful login.

---

## License

Open Source.
