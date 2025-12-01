# =============================================================================
# DDoS Defense Application Container
# =============================================================================
# Contains: NFStream + ML Inference + XDP Controller
# Base: Ubuntu 22.04 (matches development environment, good BCC support)
# =============================================================================

FROM ubuntu:22.04

LABEL maintainer="DDoS Defense System"
LABEL description="Real-time DDoS defense with XDP, ML, and NFStream"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# =============================================================================
# Install System Dependencies
# =============================================================================
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    linux-tools-common \
    linux-tools-generic \
    build-essential \
    clang \
    llvm \
    linux-headers-generic \
    libpcap-dev \
    tcpdump \
    iproute2 \
    net-tools \
    libffi-dev \
    curl \
    wget \
    procps \
    supervisor \
    redis-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Create symlink for bpftool
# =============================================================================
RUN find /usr/lib/linux-tools -name "bpftool" -type f 2>/dev/null | head -1 | xargs -I {} ln -sf {} /usr/sbin/bpftool || true

# =============================================================================
# Install Python Dependencies
# =============================================================================
RUN pip3 install --no-cache-dir \
    numpy \
    scikit-learn \
    joblib \
    nfstream \
    redis \
    requests \
    urllib3 \
    python-dateutil

# =============================================================================
# Create Application Directory Structure
# =============================================================================
WORKDIR /app

RUN mkdir -p /app/logs /app/models

# =============================================================================
# Copy Application Files
# =============================================================================

# Copy ML models
COPY models/trained_models.pkl /app/models/
COPY models/preprocessing_objects.pkl /app/models/

# Copy XDP program
COPY app/xdp_ip_blacklist_bcc.c /app/

# Copy Python scripts
COPY app/nfstream_agent.py /app/
COPY app/ml_infer_service.py /app/
COPY app/xdp_controller.py /app/

# Copy entrypoint and supervisor config
COPY docker/entrypoint.sh /app/
COPY docker/supervisord.conf /etc/supervisor/conf.d/ddos-defense.conf

# Make scripts executable
RUN chmod +x /app/*.py /app/entrypoint.sh

# =============================================================================
# Environment Variables (defaults, can be overridden)
# =============================================================================
ENV NETWORK_INTERFACE=ens33
ENV CAPTURE_INTERFACE=ens33
ENV REDIS_HOST=127.0.0.1
ENV REDIS_PORT=6379
ENV ES_HOST=http://127.0.0.1:9200
ENV ES_USER=elastic
ENV ES_PASS=jgYsL5-kztDUSd8HyiNd
ENV ARTIFACTS_DIR=/app/models
ENV XDP_PROGRAM_PATH=/app/xdp_ip_blacklist_bcc.c
ENV CONFIDENCE_THRESHOLD=0.65
ENV PYTHONUNBUFFERED=1

# =============================================================================
# Entrypoint
# =============================================================================
ENTRYPOINT ["/app/entrypoint.sh"]