#!/usr/bin/env bash

set -Eeuo pipefail

command -v curl tar

declare -a wait_pids=()

# Download JQ
curl -fsSL \
  -o './jq-linux-amd64' \
  'https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64' &
wait_pids+=($!)

# Download YQ
curl -fsSL \
  -o './yq-linux-amd64' \
  'https://github.com/mikefarah/yq/releases/download/v4.30.8/yq_linux_amd64' &
wait_pids+=($!)

# Download Helm
(
  curl -fsSL \
    'https://get.helm.sh/helm-v3.11.0-linux-amd64.tar.gz' |
    tar -xzO linux-amd64/helm \
    > './helm-linux-amd64'
) &
wait_pids+=($!)

# Download Kubectl
curl -fsSL \
  -o './kubectl-linux-amd64' \
  'https://dl.k8s.io/release/v1.24.10/bin/linux/amd64/kubectl' &
wait_pids+=($!)

# Wait for Downloads to Complete
wait "${wait_pids[@]}"
echo "Downloads Complete"