#!/usr/bin/env bash

# 1 - Docker Context (unused)
# 2 - Fully Qualified Container Image Name
# 3 - Container Instance Name

declare \
  os_imgs_docker_context \
  os_imgs_image_name \
  os_imgs_instance_name

os_imgs_docker_context="${1:?"Docker run script expects the path to the Docker Context"}"
os_imgs_image_name="${2:?"Docker run script expects a Fully Qualified Container Image Name"}"
os_imgs_instance_name="${3:?"Docker run script expects the desired name of the container instace"}"

# For now just cleanup
docker rm -f "${os_imgs_instance_name}" || true

# Start the Container
docker run \
  -d \
  --name "${os_imgs_instance_name}" \
  --restart always \
  -p '137:137/udp' \
  -p '138:138/udp' \
  -p '139:139' \
  -p '445:445' \
  "${os_imgs_image_name}"

success "container '${os_imgs_instance_name}' is ready"