FROM python:3.11-slim

LABEL pad-onap.vnf="blackhole" \
      pad-onap.version="1.0" \
      description="PAD-ONAP VNF: iptables-based null-routing blackhole (1 vCPU, 1GB)"

WORKDIR /app
COPY blackhole.py .

RUN pip install --no-cache-dir flask prometheus-client

EXPOSE 8004

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8004/health')"

CMD ["python3", "blackhole.py", "--port", "8004"]
