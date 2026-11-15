FROM python:3.13.18-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC \
    DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/

# Non-root; /data is the only writable path (SQLite config store + job state).
RUN useradd --system --uid 10001 --no-create-home aiops \
 && mkdir /data && chown aiops /data
USER aiops
VOLUME /data
EXPOSE 8095

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8095/api/v1/health', timeout=3)"]

CMD ["python", "-u", "main.py"]
