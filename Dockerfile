# ── HawkEye — Dockerfile optimisé ───────────────────────────────────────────
# Single-stage : toutes les dépendances sont des wheels pures
#
# Construction :
#   docker build -t hawkeye .
#
# Utilisation :
#   docker run --rm --cap-add=NET_RAW hawkeye              # Sniffer
#   docker run --rm -p 5000:5000 hawkeye dashboard         # Dashboard
#   docker run --rm hawkeye --help                         # Aide
#
# Chemins importants :
#   /app              → Code source
#   /data             → Volume persistant (DB, logs)

FROM python:3.11-slim

# Métadonnées OCI
LABEL org.opencontainers.image.title="HawkEye"
LABEL org.opencontainers.image.description="Sniffer DNS & Détecteur d'Anomalies"
LABEL org.opencontainers.image.version="2.1.0"
LABEL org.opencontainers.image.url="https://github.com/GhostStx/HawkeyeSee"
LABEL org.opencontainers.image.licenses="MIT"

# Installation : libpcap (runtime Scapy) + dépendances Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie + installation des dépendances (layer cache séparé)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    find /usr/local -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

# Copie du code source
COPY . .

# Répertoire de données persistant
RUN mkdir -p /data && chmod 777 /data
VOLUME ["/data"]

EXPOSE 5000

# Healthcheck : vérifie que l'API du dashboard répond
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" 2>/dev/null || exit 1

# Point d'entrée
ENV HAWKEYE_DB_PATH=/data/hawkeye.db
ENTRYPOINT ["python3", "-m", "hawkeye", "--db", "/data/hawkeye.db"]
CMD []
