# Docker Swarm Trivy exporter

![](https://img.shields.io/docker/pulls/neuroforgede/docker-swarm-trivy-exporter.svg)

*Docker Swarm Trivy exporter* exposes trivy scan results to prometheus metrics.

Proudly made by [NeuroForge](https://neuroforge.de/) in Bayreuth, Germany.

## Use in a Docker Swarm deployment

Deploy:

```yaml
version: "3.8"

services:
  docker-swarm-trivy-exporter:
    image: ghcr.io/neuroforgede/docker-swarm-trivy-exporter:0.1.0
    networks:
      - net
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      TRIVY_SLOW: "true"
    deploy:
      mode: replicated
      replicas: 1
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M
```

prometheus.yml

```yaml
# ...
scrape_configs:
  - job_name: 'docker-swarm-trivy-exporter'
    dns_sd_configs:
    - names:
      - 'tasks.docker-swarm-trivy-exporter'
      type: 'A'
      port: 9000
```

A monitoring solution based on the original swarmprom that includes this can be found at our [Swarmsible Stacks repo](https://github.com/neuroforgede/swarmsible-stacks)
