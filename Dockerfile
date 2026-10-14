# VPSPilot API (control plane). Built by deploy/compose.yaml.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
# /app/data: encrypted export/import files (a volume in compose.yaml).
RUN uv sync --frozen --no-dev && useradd --system --uid 1001 vpspilot \
    && mkdir -p /app/data && chown -R vpspilot /app
ENV PATH=/app/.venv/bin:$PATH
USER vpspilot
EXPOSE 8000
# Migrations run on every start, so upgrading is: new image + restart.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
