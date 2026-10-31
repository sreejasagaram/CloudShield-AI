FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8080 \
    CLOUDSHIELD_VECTOR_DB_DIR=/var/lib/cloudshield/chroma \
    CLOUDSHIELD_DATABASE_PATH=/var/lib/cloudshield/cloudshield.sqlite3

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY data/configs ./data/configs
COPY data/rag/knowledge.json ./data/rag/knowledge.json

RUN groupadd --system --gid 10001 cloudshield \
    && useradd --system --uid 10001 --gid cloudshield cloudshield \
    && mkdir -p /var/lib/cloudshield/chroma \
    && chown -R cloudshield:cloudshield /var/lib/cloudshield

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT', '8080') + '/health', timeout=3)"

CMD ["sh", "-c", "exec waitress-serve --host=0.0.0.0 --port=${PORT:-8080} cloudshield.api:app"]
