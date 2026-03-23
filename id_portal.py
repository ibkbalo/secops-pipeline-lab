import jwt
import datetime

# THE "CRYPTO-SECRET" OF THE PERIMETER (Project 21 Secret)
# In a Day Job at Amazon, this is stored in a 'Vault' (Project 22)
SECRET_KEY = "ACNSE_SUPER_SECRET_SECURITY_PASS"

def generate_identity_token(username, role):
    # THE "IDENTITY" PAYLOAD (Who are you and what is your Role?)
    payload = {
        'user': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # Token expires in 30 mins
    }
    
    # THE "ID CARD" CREATION (Signing the JWT)
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

if __name__ == "__main__":
    print("🛡️ IAM: Initializing Identity Portal...")
    user_token = generate_identity_token("ibukun_admin", "ADMIN")
    print(f"\n✅ TOKEN GENERATED (Copy this for the next step):\n{user_token}")