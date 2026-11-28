FROM python:3.13.18-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC \
    DATA_DIR=/data

WORKDIR /app

# Debian security updates on top of the base image (the base tag is rebuilt upstream only from time to time).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# pip is needed only to install; removing it also removes its vendored libraries (msgpack, urllib3, pkg_resources),
# which the image scan would otherwise report. The console never installs anything at runtime.
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3.13/ensurepip

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
