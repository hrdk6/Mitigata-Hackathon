FROM python:3.12-slim

WORKDIR /app

# System tools NightTrace shells out to:
#   iputils-ping — ICMP TTL signal for OS fingerprinting and liveness
#   nmap         — full (-p-) port scan + service/version detection
#   wget, unzip  — fetch the nuclei release binary below
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iputils-ping nmap wget unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# nuclei (ProjectDiscovery) — the community vulnerability-template engine that
# gives NightTrace broad, up-to-date web/network coverage. Fetch the latest
# linux/amd64 release binary (best-effort: NightTrace runs fine without it).
RUN ( url="$(wget -qO- https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
             | grep -o 'https://[^"]*linux_amd64\.zip' | head -n1)" \
   && wget -q "$url" -O /tmp/nuclei.zip \
   && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
   && chmod +x /usr/local/bin/nuclei \
   && rm -f /tmp/nuclei.zip ) \
 || echo "WARNING: nuclei binary install skipped"

# NOTE: nuclei templates are NOT pulled at build time (it is slow and needs
# network). NightTrace detects missing templates and skips nuclei cleanly, so
# builds stay fast. Enable nuclei's templates once, after the container is up:
#     docker exec nighttrace nuclei -update-templates

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000
# Bring up the live dashboard around the calibrated scope (config/scope.yaml).
# No demo, no hardcoded targets: calibrate the scope in the UI (/scope-editor or
# /discover) and press Run, or drop in a scope.yaml and it auto-starts on boot.
CMD ["nighttrace", "serve", "--scope", "config/scope.yaml", "--host", "0.0.0.0", "--port", "8000"]
