#!/usr/bin/env bash

# 1 - Docker Context (unused)
# 2 - Fully Qualified Container Image Name
# 3 - Container Instance Name

declare \
  xoa_docker_context \
  xoa_image_name \
  xoa_instance_name

xoa_docker_context="${1:?"Docker run script expects the path to the Docker Context"}"
xoa_image_name="${2:?"Docker run script expects a Fully Qualified Container Image Name"}"
xoa_instance_name="${3:?"Docker run script expects the desired name of the container instace"}"

debug "xoa_docker_context=${xoa_docker_context:-}"
debug "xoa_image_name=${xoa_image_name:-}"
debug "xoa_instance_name=${xoa_instance_name:-}"

# For now just cleanup
docker rm -f "${xoa_instance_name}" || true
docker volume rm xoa-data xoa-db || true

# Create the Volumes if they don't exist
{
  docker volume ls --format '{{ .Name }}' |
  grep -q 'xoa-data'
} || docker volume create xoa-data
{
  docker volume ls --format '{{ .Name }}' |
  grep -q 'xoa-db'
} || docker volume create xoa-db

# Run the Container
docker run \
  -d \
  --name "${xoa_instance_name}" \
  --restart always \
  --stop-timeout 60 \
  -e 'HTTPS_PORT=443'\
  -e 'REDIRECT_TO_HTTPS=true' \
  -p "8443:443" \
  -v xoa-data:/var/lib/xo-server \
  -v xoa-db:/var/lib/redis \
  "${xoa_image_name}"

# Instal xo-cli
if ! docker exec "${xoa_instance_name}" bash -c "command -v xo-cli"; then
  info "Installing xo-cli tool"
  docker exec "${xoa_instance_name}" \
    npm install --global xo-cli  
fi

# Wait till Login Page is ready
info "Waiting for Login Page to be ready"
until docker exec "${xoa_instance_name}" curl -kL "https://127.0.0.1" 2>/dev/null | grep -q 'Xen Orchestra'; do
  sleep 1
  info "Waiting for Login Page to be ready"
done
success "container '${xoa_instance_name}' is ready"
