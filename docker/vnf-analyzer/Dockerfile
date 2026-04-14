FROM python:3.11-slim

LABEL pad-onap.vnf="analyzer" \
      pad-onap.version="1.0" \
      description="PAD-ONAP VNF: Packet capture + feature re-extraction for M1 telemetry (2 vCPU, 4GB)"

WORKDIR /app
COPY analyzer.py .

RUN pip install --no-cache-dir flask prometheus-client

EXPOSE 8003

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8003/health')"

CMD ["python3", "analyzer.py", "--port", "8003"]
