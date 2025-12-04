FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.11-slim
ENV TZ=UTC
WORKDIR /app
RUN apt-get update && apt-get install -y cron tzdata && 
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && 
    dpkg-reconfigure -f noninteractive tzdata && 
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /install /usr/local
COPY app ./app
COPY scripts ./scripts
COPY cron ./cron
COPY student_private.pem ./student_private.pem
COPY student_public.pem ./student_public.pem
COPY instructor_public.pem ./instructor_public.pem
RUN chmod 644 student_private.pem student_public.pem instructor_public.pem && 
    chmod +x scripts/log_2fa_cron.py && 
    chmod 644 cron/2fa-cron && 
    crontab cron/2fa-cron && 
    mkdir -p /data /cron && 
    chmod 755 /data /cron
VOLUME ["/data", "/cron"]
EXPOSE 8080
CMD service cron start && uvicorn app.main:app --host 0.0.0.0 --port 8080
