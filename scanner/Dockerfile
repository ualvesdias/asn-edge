FROM golang:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

# Only the PD tools still used by the pipeline
RUN /go/bin/pdtm -i dnsx,httpx,katana,naabu,nuclei,tlsx

FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/state

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    tini \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.pdtm/go/bin/ /usr/local/bin/

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY pd_pipeline_pro.py /app/pd_pipeline_pro.py
#COPY refresh_bgp_db.py /app/refresh_bgp_db.py
COPY execution_engine.py /app/execution_engine.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
 && mkdir -p /data /config /state

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
