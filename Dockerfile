#########################
# Stage 1: Builder
#########################
FROM python:3.11-slim AS builder

# Workdir inside image
WORKDIR /app

# Install build deps if cryptography needs them
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file and install (cached layer)
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt


#########################
# Stage 2: Runtime
#########################
FROM python:3.11-slim AS runtime

# ----- Timezone -----
ENV TZ=UTC

# Install system deps: cron + tzdata
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Configure timezone to UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Workdir
WORKDIR /app

# Copy installed python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code (everything in repo folder)
COPY . /app

# ----- Cron setup -----

# Copy cron configuration
COPY cron/2fa-cron /app/cron/2fa-cron

RUN chmod 0644 /app/cron/2fa-cron && \
    crontab /app/cron/2fa-cron

# ----- Volumes -----
# /data: encrypted/decrypted seed
# /cron: cron logs or other outputs
RUN mkdir -p /data /cron && chmod 755 /data /cron
VOLUME ["/data", "/cron"]

# ----- Networking -----
EXPOSE 8080

# ----- Start cron + API server -----
# cron runs as daemon, uvicorn stays in foreground
CMD ["/bin/sh", "-c", "cron && uvicorn main:app --host 0.0.0.0 --port 8080"]


COPY scripts /app/scripts