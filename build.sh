 #!/bin/bash
 docker build -f Dockerfile \
    -t neuroforgede/docker-engine-events-exporter:latest \
    -t neuroforgede/docker-engine-events-exporter:0.1 \
    .

docker push neuroforgede/docker-engine-events-exporter:latest
docker push neuroforgede/docker-engine-events-exporter:0.1