# Local builds retain a convenient tag default. Production and CI also set
# REQUIRE_BASE_IMAGE_DIGEST=true, which makes the build fail unless BASE_IMAGE
# is an immutable sha256 reference. See docs/supply-chain/README.md.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE} AS runtime

ARG BASE_IMAGE
ARG REQUIRE_BASE_IMAGE_DIGEST=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

# Validate the reference inside the build as a second line of defence. The
# production Compose file and security workflow turn this guard on; no digest is
# hard-coded here because it must be selected and verified by the operator.
RUN if [ "$REQUIRE_BASE_IMAGE_DIGEST" = "true" ]; then \
        printf '%s' "$BASE_IMAGE" \
          | grep -Eq '^[^[:space:]@]+@sha256:[0-9a-f]{64}$' \
          || { echo >&2 'BASE_IMAGE must be a digest-pinned sha256 reference'; exit 1; }; \
    fi

WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app app \
    && pip install --no-cache-dir uv==0.11.15

# uv.lock được COPY để cài đặt tái lập được (Bài 8 §chuỗi cung ứng).
# Build dừng ngay nếu lockfile thiếu hoặc không còn khớp pyproject.toml.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-dev --frozen

COPY src ./src
COPY scripts/migrate_database.py ./scripts/migrate_database.py
COPY scripts/enforce_retention.py ./scripts/enforce_retention.py
COPY scripts/migrate_envelope_encryption.py ./scripts/migrate_envelope_encryption.py
COPY scripts/rewrap_deks.py ./scripts/rewrap_deks.py
COPY scripts/high_security_app_entrypoint.sh ./scripts/high_security_app_entrypoint.sh
COPY run_app.py ./run_app.py
RUN chown -R app:app /app
ENV HOME=/app
USER app

EXPOSE 8000

# Liveness probe: Docker/Compose tự khởi động lại container khi ứng dụng treo,
# phục vụ tính Sẵn sàng (Availability) trong C.I.A — Bài 1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", \
         "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"]

# Không tin các proxy header theo mặc định. Bản Compose production bật chúng
# riêng sau Caddy, còn bản local được publish thẳng nên không thể bị giả IP qua
# X-Forwarded-For.
CMD ["/app/.venv/bin/uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
