FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends wget apt-transport-https gnupg lsb-release && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends trivy && \
    rm -rf /var/lib/apt/lists/*

ADD docker /opt/trivy-exporter
WORKDIR /opt/trivy-exporter

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "./trivy_prom.py"]
