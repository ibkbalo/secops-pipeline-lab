# THE ACNSE GOLDEN IMAGE (Project 25)
FROM python:3.12-slim

# OS HARDENING: LAYER 1
RUN apt-get update && apt-get install -y nmap curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p security-operations

# DEPENDENCY MANAGEMENT: LAYER 2
RUN pip install flask pyjwt

# INJECTING THE PROJECT 25 GATEWAY
COPY . .

# DETERMINISTIC PORT MAPPING (Project 1-5 Alignment)
EXPOSE 5000

# HARDENING: Create a non-privileged user (Project 6 Alignment)
RUN useradd -m sentinel_user && chown -R sentinel_user /app
USER sentinel_user

# OPERATIONAL BOOTSTRAP
CMD ["python", "app.py"]