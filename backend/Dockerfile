FROM python:3.14-slim

# Disable Python bytecode caching to ensure code changes take effect
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV EVENTLET_NO_GREENDNS=yes

WORKDIR /app


# Install system dependencies, Nmap, and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    nmap \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery Nuclei binary (supports ARM64 Apple Silicon & AMD64)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_arm64.zip -O nuclei.zip; \
    else \
        wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip -O nuclei.zip; \
    fi && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir safety

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Start Gunicorn with an eventlet worker to support real-time Socket.IO# Start Gunicorn with an eventlet worker for high-concurrency and Socket.IO support
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "src.th.webapp:app"]