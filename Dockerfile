FROM python:3.12-slim
RUN apt-get update && apt-get install -y \
    tcpdump sqlite3 && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir scapy
WORKDIR /app
COPY sniffer.py .
CMD ["python", "sniffer.py"]