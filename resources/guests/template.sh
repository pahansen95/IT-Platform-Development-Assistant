#!/usr/bin/env bash

set -Eeuo pipefail

command -v jq yq

while :; do
  unset name || true
  declare name; name="${1:-}"; shift
  if [[ -z "${name}" ]]; then
    break
  fi
  {
    yq -o json |
      jq -cr --arg name "${name}" '.metadata.name = $name' |
      yq -o yaml -P
  } > "./${name}.yaml" << 'EOF'
metadata:
  name: 
  uuid: 
spec:
  qemu:
    bin: /usr/bin/qemu-system-x86_64
  image:
    name: ubuntu-22.04-amd64
    size: 16G
  cpu: 2
  memory: 4096
  network:
    bridge: uplink
    hwaddr: 
  volumes:
    - size: 64G
      storageClass: slow
      uuid: 
    - size: 16G
      storageClass: fast
      uuid:
  users:
    - name: dev
      sshKeys:
        - "~/.ssh/dev-homelab.pub"
      shell: /bin/bash
EOF
done


