FROM python:3.11-slim

LABEL maintainer="PAD-ONAP"
LABEL description="gNMI network metrics simulator for PAD-ONAP testbed"

WORKDIR /app
COPY main.py .

# No external dependencies — stdlib only
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python3", "main.py"]
