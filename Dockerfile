# Pin the base image by digest for supply-chain integrity. Obtain the current digest with:
#   docker buildx imagetools inspect python:3.12-slim --format '{{println .Manifest.Digest}}'
# then build with:  docker build --build-arg BASE_IMAGE=python:3.12-slim@sha256:<digest> .
# The tag default keeps local builds working; production/CI should pass a digest-pinned ref.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app app \
    && pip install --no-cache-dir uv==0.10.0

# uv.lock được COPY để cài đặt tái lập được (Bài 8 §chuỗi cung ứng).
# Build dừng ngay nếu lockfile thiếu hoặc không còn khớp pyproject.toml.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-dev --frozen

COPY src ./src
COPY scripts/migrate_database.py ./scripts/migrate_database.py
COPY run_app.py ./run_app.py
RUN chown -R app:app /app
USER app

EXPOSE 8000

# Liveness probe: Docker/Compose tự khởi động lại container khi ứng dụng treo,
# phục vụ tính Sẵn sàng (Availability) trong C.I.A — Bài 1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", \
         "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"]

# Chỉ image Compose chuẩn mới bật proxy headers: cổng ứng dụng không publish ra
# host và Caddy là peer duy nhất trên mạng edge, nên client không thể tự chèn XFF.
CMD ["/app/.venv/bin/uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
