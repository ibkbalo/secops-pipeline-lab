"""
SENTINEL STACKS: THE PROJECT 25 IDENTITY GATEWAY (v1.5)
Integrating Projects 21-25: JWT Authentication & Sovereign Encryption
"""

import os
import jwt
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request

app = Flask(__name__)

# THE SOVEREIGN SECRET: Fetched from Environment (Project 22 Alignment)
app.config['SECRET_KEY'] = os.getenv("SENTINEL_SECRET", "super-secret-fallback-key")

# --- IDENTITY GUARD: THE BOUNCER (Project 21 logic) ---
def sentinel_token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"alert": "SENTINEL-ID: Missing Identity Token"}), 401
        
        try:
            # Validating the Digital "ID Card"
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except Exception:
            return jsonify({"alert": "SENTINEL-ID: Forensic Identity Breach"}), 401
        
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# --- THE CROWN JEWELS (Project 12 Database Simulated) ---
@app.route('/health')
def health_check():
    return jsonify({
        "status": "SENTINEL-PASS",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/vault-data')
@sentinel_token_required
def secure_data():
    return jsonify({
        "identity_status": "AUTHENTICATED",
        "data_payload": "Top Secret Sovereign Intel Extracted Successfully"
    })

if __name__ == "__main__":
    # Project 25 Bootstrapper
    app.run(host='0.0.0.0', port=5000)