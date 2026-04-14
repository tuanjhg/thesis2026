FROM python:3.11-slim

LABEL pad-onap.vnf="scrubber" \
      pad-onap.version="1.0" \
      description="PAD-ONAP VNF: Stateful SYN proxy + rate limiting scrubber (8 vCPU, 16GB)"

WORKDIR /app
COPY scrubber.py .

RUN pip install --no-cache-dir flask prometheus-client scapy 2>/dev/null || \
    pip install --no-cache-dir flask prometheus-client

EXPOSE 8001

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["python3", "scrubber.py", "--port", "8001"]
