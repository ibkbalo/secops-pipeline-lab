import os
import jwt
from flask import Flask, jsonify, request
from functools import wraps
from forensic_logger import setup_forensic_logger
from rate_limiter import rate_limit

app = Flask(__name__)

# PROJECT 22: THE VAULT INJECTION
SECRET_KEY = os.environ.get("ACNSE_MASTER_SECRET")

# PROJECT 23: THE FORENSIC DATA STREAM
audit_logger = setup_forensic_logger()

# PROJECT 21: THE IDENTITY GATEWAY (DECORATOR)
def identity_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "IDENTITY_MISSING", "message": "Zero-Trust Enforcement: Missing Cryptographic ID."}), 401
        
        try:
            # PROJECT 22: VERIFY AGAINST THE VAULT SECRET
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # PROJECT 23: FORENSIC TELEMETRY (JSON LOGGING)
            audit_logger.info(f"AUTHORIZED_ACCESS: Identity {data['user']} | Role: {data['role']}")
        except Exception as e:
            return jsonify({"error": "IDENTITY_TAMPERED", "message": "Forensic Alert: Invalid or Expired Signature."}), 401
            
        return f(*args, **kwargs)
    return decorated

# PROJECT 24: THE CIRCUIT BREAKER (RESILIENCY)
@app.route('/crown-jewels')
@identity_required
@rate_limit(limit=5, window=60) # Only 5 requests per 60 seconds
def crown_jewels():
    return jsonify({
        "status": "SUCCESS",
        "access": "GRANTED",
        "data": "💎 CROWN JEWELS: Welcome, Architect. The Project 12 Database is SECUREly accessible."
    })

if __name__ == '__main__':
    print("🛡️ ACNSE: Secure Vault Gateway Online (Zero-Trust + Resiliency Active)")
    app.run(host='0.0.0.0', port=5000)