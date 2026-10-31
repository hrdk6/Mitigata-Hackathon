FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000
# Self-contained demo: starts the localhost lab, runs the engine, serves the
# live dashboard. For a real engagement, mount a scope file and run:
#   docker compose run --rm nighttrace nighttrace run --scope /app/config/scope.yaml
CMD ["python", "run_demo.py", "--serve", "--api-port", "8000"]
