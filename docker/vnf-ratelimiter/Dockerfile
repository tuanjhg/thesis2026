FROM python:3.11-slim

LABEL pad-onap.vnf="ratelimiter" \
      pad-onap.version="1.0" \
      description="PAD-ONAP VNF: Token-bucket per-flow rate limiter (2 vCPU, 2GB)"

WORKDIR /app
COPY ratelimiter.py .

RUN pip install --no-cache-dir flask prometheus-client

EXPOSE 8002

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/health')"

CMD ["python3", "ratelimiter.py", "--port", "8002"]
