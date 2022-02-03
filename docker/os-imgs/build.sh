#!/usr/bin/env bash

# 1 - Docker Context
# 2 - Fully Qualified Container Image Name

declare \
  os_imgs_docker_context \
  os_imgs_cntr_name

os_imgs_docker_context="${1:?"Docker build script expects the path to the Docker Context"}"
os_imgs_cntr_name="${2:?"Docker build script expects a Fully Qualified Container Image Name"}"

docker build \
  -t "${os_imgs_cntr_name}" \
  -f "${os_imgs_docker_context}/Dockerfile" \
  "${os_imgs_docker_context}"

docker image inspect "${os_imgs_cntr_name}" |& 
  trace "$(cat)"