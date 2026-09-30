# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Base refs are pinned by digest (the tag is informational); the pipeline's
# reproducible-build control fails on a floating FROM. Bump them in a
# reviewed PR.
FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS builder
COPY --from=uv /uv /bin/
# No bytecode compilation: .pyc files are the usual source of build-to-build
# differences, and the runtime root filesystem is read-only anyway.
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=0 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY manage.py gunicorn.conf.py ./
COPY config ./config
COPY notes ./notes
COPY templates ./templates
COPY static ./static
# collectstatic imports the settings, which refuse to load without a key;
# this one exists only for this step and is never in the image.
RUN DJANGO_SECRET_KEY=collectstatic-build-step-only \
    /app/.venv/bin/python manage.py collectstatic --noinput \
 && mkdir /data

# The runtime stage only copies files and deletes: its layers depend on
# nothing but the inputs (and SOURCE_DATE_EPOCH for timestamps).
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS runtime
# The pinned base lags Debian's openssl security fixes (CVE-2026-75804,
# CVE-2026-84782 fixed in 3.5.7-1~deb13u3). Upgrade only those packages, and
# drop apt's lists/logs/caches in the same layer: they embed timestamps and
# would break the reproducible-build check. Remove this once the pinned base
# digest is bumped to an image that already carries the fix.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends --only-upgrade \
      openssl libssl3t64 openssl-provider-legacy \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /var/cache/ldconfig \
      /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/apt-history.log
# pip isn't used at runtime, and its vendored libraries (msgpack, ...) carry
# CVEs the image scan would rightly block on.
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-*.dist-info /usr/local/bin/pip*
WORKDIR /app
COPY --from=builder /app /app
# SQLite lives here; in Kubernetes it is a volume, so this only matters
# when the image runs without one.
COPY --from=builder --chown=10001:10001 /data /data
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_DB_PATH=/data/db.sqlite3 \
    HOME=/tmp
# Numeric, so runAsNonRoot can verify it without an /etc/passwd entry.
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/healthz', headers={'Host': 'localhost'}), timeout=4)"]
CMD ["gunicorn", "-c", "gunicorn.conf.py"]
