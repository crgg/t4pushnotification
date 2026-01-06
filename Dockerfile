FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/storage/apns_keys /app/logs && \
    chmod 700 /app/storage/apns_keys

RUN useradd -m -u 1000 apns && \
    chown -R apns:apns /app

USER apns
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)"

CMD ["gunicorn", "--config", "gunicorn_config.py", "app:app"]