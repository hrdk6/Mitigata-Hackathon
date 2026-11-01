FROM python:3.12-slim

WORKDIR /app

# iputils-ping gives OS fingerprinting its TTL signal (the slim image omits it).
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000
# Bring up the live dashboard around the calibrated scope (config/scope.yaml).
# No demo, no hardcoded targets: calibrate the scope in the UI (/scope-editor or
# /discover) and press Run, or drop in a scope.yaml and it auto-starts on boot.
CMD ["nighttrace", "serve", "--scope", "config/scope.yaml", "--host", "0.0.0.0", "--port", "8000"]
