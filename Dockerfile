# VPSPilot API (control plane). Built by deploy/compose.yaml.
FROM python:3.12-slim
# UV_NO_CACHE: uv's download cache would otherwise ship in the image (~120 MB).
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    UV_NO_CACHE=1
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
# /app/data: encrypted export/import files (a volume in compose.yaml).
# pip comes with the base image but nothing uses it (uv installs): one less
# thing to patch.
RUN uv sync --frozen --no-dev && useradd --system --uid 1001 vpspilot \
    && mkdir -p /app/data && chown -R vpspilot /app \
    && python -m pip uninstall -y -q pip
ENV PATH=/app/.venv/bin:$PATH
USER vpspilot
EXPOSE 8000
# Migrations run on every start, so upgrading is: new image + restart.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
