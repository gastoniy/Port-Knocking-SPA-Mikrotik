FROM python:3.14-slim as builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt update && apt install -y --no-install-recommends \
    gcc python3-dev \
    # Delete cache from apt update
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/log/apt/* \
    && rm -rf /var/log/dpkg.log \
    && rm -rf /var/cache/debconf/*-old

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.14-slim as final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN groupadd -g 1001 appuser && useradd -u 1001 -g appuser appuser
RUN mkdir -p /app/data && chown appuser:appuser /app/data

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv

COPY --chown=appuser:appuser . .

USER appuser

# Mount for external data like keys and configs
VOLUME [ "/app/data" ]

# Default Listening Port
EXPOSE 62201

CMD ["python", "test-server.py"]