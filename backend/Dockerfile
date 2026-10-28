FROM python:3.11.14-slim-bookworm

ARG APP_GIT_COMMIT=unknown
ARG APP_BUILD_TIMESTAMP=unknown

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_GIT_COMMIT=${APP_GIT_COMMIT} \
    APP_BUILD_TIMESTAMP=${APP_BUILD_TIMESTAMP}

WORKDIR /opt/cyberqalqon

RUN groupadd --gid 10001 cyberqalqon \
    && useradd --uid 10001 --gid cyberqalqon --no-create-home --shell /usr/sbin/nologin cyberqalqon \
    && mkdir -p /var/lib/cyberqalqon /var/backups/cyberqalqon \
    && chown -R cyberqalqon:cyberqalqon /var/lib/cyberqalqon /var/backups/cyberqalqon

COPY requirements.txt ./requirements.txt
COPY requirements-build.txt ./requirements-build.txt
RUN python -m pip install --no-cache-dir --requirement requirements-build.txt
RUN python -m pip install --no-cache-dir --requirement requirements.txt

COPY --chown=cyberqalqon:cyberqalqon app ./app

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readiness', timeout=2).read()"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--timeout-graceful-shutdown", "30", "--no-access-log"]
