 #!/bin/bash
 docker build -f Dockerfile \
    -t neuroforgede/docker-swarm-trivy-exporter:latest \
    -t neuroforgede/docker-swarm-trivy-exporter:0.1 \
    .

docker push neuroforgede/docker-swarm-trivy-exporter:latest
docker push neuroforgede/docker-swarm-trivy-exporter:0.1