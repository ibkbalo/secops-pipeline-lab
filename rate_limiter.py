import time
from functools import wraps
from flask import request, jsonify

# THE "CIRCUIT BREAKER" STORAGE (Project 24)
# In a real Amazon cloud, we would use Redis. Here, we use a Python Dictionary.
request_history = {}

def rate_limit(limit=5, window=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Identify the 'Principal' (Who is knocking?)
            ip_address = request.remote_addr
            current_time = time.time()

            # 2. Initialize history for new IPs
            if ip_address not in request_history:
                request_history[ip_address] = []

            # 3. Clean up old requests outside the 'Window' (60 seconds)
            request_history[ip_address] = [t for t in request_history[ip_address] if current_time - t < window]

            # 4. THE ENFORCEMENT logic
            if len(request_history[ip_address]) >= limit:
                print(f"🛑 ALERT: Rate Limit Exceeded for IP: {ip_address}")
                return jsonify({
                    "error": "CIRCUIT_BREAKER_ACTIVE", 
                    "message": "Too many requests. High-Volume Anomaly Detected.",
                    "retry_after_seconds": window
                }), 429 # 429 is the Global HTTP Code for 'Too Many Requests'

            # 5. Record the successful request
            request_history[ip_address].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

if __name__ == "__main__":
    print("🛡️ ACNSE: Circuit-Breaker Engine Online. Project 24 Active.")