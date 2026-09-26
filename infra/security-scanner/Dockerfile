FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends clamav yara file ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /scanner
COPY infra/security-scanner/safe_scanner.py /scanner/safe_scanner.py
COPY scripts/malware_scanner_daemon.py /scanner/malware_scanner_daemon.py
RUN chmod 0555 /scanner/malware_scanner_daemon.py
USER 65532:65532
CMD ["python","/scanner/malware_scanner_daemon.py"]
