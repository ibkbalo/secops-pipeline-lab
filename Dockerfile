# SENTINEL STACKS: THE IMMUTABLE CLOUD FORTRESS (v2.0)
# Aligning Projects 1-25: Recon, Discovery, & Hardening
FROM python:3.12-slim

# SYSTEM HARDENING: LAYER 1 (Project 1-10 Alignment)
# Minimizing the OS surface by removing unnecessary binaries
RUN apt-get update && apt-get install -y nmap curl && rm -rf /var/lib/apt/lists/*

# ARCHITECTURE SETUP: LAYER 2
WORKDIR /app
RUN mkdir -p security-operations

# DEPENDENCY MANAGEMENT: LAYER 3
# Enforcing deterministic version control for Python artifacts
RUN pip install flask pyjwt

# INJECTING THE PROJECT 25 GATEWAY
COPY . .

# PRIVILEGE ISOLATION: LAYER 4 (Project 6 Alignment)
# Escalating defense by de-escalating user permissions
RUN useradd -m sentinel_user && chown -R sentinel_user /app
USER sentinel_user

# DETERMINISTIC PORT MAPPING (Project 1-5 Discovery)
EXPOSE 5000

# OPERATIONAL BOOTSTRAP
CMD ["python", "app.py"]