FROM python:3.12-slim

# iptables is how Portcullis blocks addresses on Linux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /build/
COPY src /build/src
RUN pip install --no-cache-dir /build && rm -rf /build

# The config and the database live here (mount a volume).
WORKDIR /data
VOLUME /data
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=3).status == 200 else 1)"

ENTRYPOINT ["portcullis"]
CMD ["run", "-c", "/data/portcullis.toml"]
