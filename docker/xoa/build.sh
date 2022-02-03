#!/usr/bin/env bash

# 1 - Docker Context (ignored)
# 2 - Fully Qualified Container Image Name

declare \
  xoa_docker_context \
  xoa_cntr_name

xoa_docker_context="${1:?"Docker build script expects the path to the Docker Context"}"
xoa_cntr_name="${2:?"Docker build script expects a Fully Qualified Container Image Name"}"

git clone \
  "https://github.com/ronivay/xen-orchestra-docker.git" \
  "${TEMP_DIR}/xoa"

docker build \
  -t "${xoa_cntr_name}" \
  -f "${TEMP_DIR}/xoa/Dockerfile" \
  "${TEMP_DIR}/xoa"

docker image inspect "${xoa_cntr_name}" |& 
  trace "$(cat)"
