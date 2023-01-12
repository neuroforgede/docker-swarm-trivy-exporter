#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2022 NeuroForge GmbH & Co. KG <https://neuroforge.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import docker
from prometheus_client import start_http_server, Gauge
import os
import subprocess
import json
from time import sleep
import traceback
from typing import Dict, Any

APP_NAME = "Docker Swarm Trivy exporter"

CVES = Gauge('docker_swarm_trivy_service_cves',
             'Docker Swarm Trivy Service CVEs',
             [
                 'trivy_schema_version',
                 'trivy_result_target',
                 'trivy_result_class',
                 'trivy_result_type',
                 'trivy_vulnerability_severity',
                 'service_name',
                 'image',
                 'image_short'
             ])

PROMETHEUS_EXPORT_PORT = int(os.getenv('PROMETHEUS_EXPORT_PORT', '9000'))
SCAN_INTERVAL_SECONDS = int(os.getenv('SCAN_INTERVAL_SECONDS', '3600'))


def print_timed(msg):
    to_print = '{} [{}]: {}'.format(
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'docker_swarm_trivy_service_cves',
        msg)
    print(to_print)


def run_trivy(last_labels: Dict[Any, Any]):
    _seen_labels = {}

    client = docker.DockerClient()
    try:
        images = set()
        service_list = {}
        failed_image_scans = set()

        for service in client.services.list():
            for task in service.tasks():
                image_name = task['Spec']['ContainerSpec']['Image']
                images.add(image_name)

                if image_name not in service_list:
                    service_list[image_name] = set()
                service_list[image_name].add(service.name)

        for image in images:
            try:
                print_timed(f"scanning image {image}")
                trivy = subprocess.run([
                        "trivy",
                        "--quiet",
                        "image",
                        "-f",
                        "json",
                        "--cache-dir=/trivycache",
                        image
                    ],
                    capture_output=True,
                    env={
                        "TMPDIR": "/trivycache/tmp",
                        **os.environ,
                    }
                )

                if trivy.returncode != 0:
                    print(trivy.stderr)
                    failed_image_scans.add(image)
                    continue

                try:
                    trivy_response = json.loads(trivy.stdout)
                except json.decoder.JSONDecodeError:
                    print(trivy.stderr)
                    failed_image_scans.add(image)
                    continue

                _schema_version = str(trivy_response.get("SchemaVersion", ""))

                results = trivy_response.get("Results", [])
                for result in results:
                    _target = result.get("Target", "")
                    _class = result.get("Class", "")
                    _type = result.get("Type", "")

                    vulnerabilities = result.get('Vulnerabilities', [])

                    _severity_counts = {}

                    for vulnerability in vulnerabilities:
                        _severity = vulnerability.get("Severity", "UNKNOWN")
                        if _severity not in _severity_counts:
                            _severity_counts[_severity] = 0

                        _severity_counts[_severity] += 1

                    for _service in service_list[image]:
                        for _severity, _severity_count in _severity_counts.items():
                            short_image_name = image.split('@', 1)[0]
                            _labels = {
                                'trivy_schema_version': _schema_version,
                                'trivy_result_target': _target,
                                'trivy_result_class': _class,
                                'trivy_result_type': _type,
                                'trivy_vulnerability_severity': _severity,
                                'service_name': _service,
                                'image': image,
                                'image_short': short_image_name
                            }
                            CVES.labels(**_labels).set(
                                _severity_count
                            )
                            _seen_labels[frozenset(
                                sorted(_labels.items()))] = _labels
            except:
                traceback.print_exc()
                raise

        # clean metrics that are not present anymore
        _dead_labels = set(last_labels.keys()) \
            - set(_seen_labels.keys())
        for _dead_labels_key in _dead_labels:
            _label_data = last_labels[_dead_labels_key]

            if _label_data['image'] in failed_image_scans:
                continue

            _label_values = _label_data.values()
            CVES.remove(*_label_values)
    finally:
        client.close()

    return _seen_labels


if __name__ == '__main__':
    isExist = os.path.exists("/trivycache/tmp")
    if not isExist:
        os.makedirs("/trivycache/tmp")
        
    print_timed(f'Start prometheus client on port {PROMETHEUS_EXPORT_PORT}')
    start_http_server(PROMETHEUS_EXPORT_PORT, addr='0.0.0.0')
    try:
        _last_labels = {}
        while True:
            _last_labels = run_trivy(_last_labels)
            sleep(SCAN_INTERVAL_SECONDS)

    except docker.errors.APIError:
        pass
