# ── HawkEye — Dockerfile ────────────────────────────────────────────────────
# Multi-stage : une image légère pour le sniffer + dashboard

# === Stage 1 : Base ===
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# === Stage 2 : Dépendances ===
FROM base AS dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# === Stage 3 : Final ===
FROM dependencies AS final

COPY . .

# Création des répertoires
RUN mkdir -p logs

# Port du dashboard
EXPOSE 5000

# Par défaut : mode sniffer (nécessite --cap-add=NET_RAW en Docker)
# Pour le dashboard : docker run -p 5000:5000 hawkeye dashboard
ENTRYPOINT ["python", "-m", "hawkeye"]
CMD []
