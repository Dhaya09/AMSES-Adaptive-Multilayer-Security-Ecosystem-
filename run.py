"""
AMSES - Entry Point
run.py

Start the application with:
    python run.py
"""

import os
from app import create_app
import config

# Ensure log directory exists
os.makedirs(config.LOG_DIR, exist_ok=True)
for log_file in [config.LOG_AUTH, config.LOG_RISK,
                 config.LOG_ALERTS, config.LOG_BLOCKED, config.LOG_EVENTS]:
    if not os.path.exists(log_file):
        open(log_file, "w").close()

app = create_app()

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║   AMSES - Adaptive Multilayer Security Ecosystem             ║
║   Starting on http://127.0.0.1:5000                          ║
║                                                              ║
║   Demo credentials:                                          ║
║     Username: admin                                          ║
║     Password: SecurePass@123                                 ║
║                                                              ║
║   Dashboard:  http://127.0.0.1:5000/dashboard                ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        use_reloader=False,
    )