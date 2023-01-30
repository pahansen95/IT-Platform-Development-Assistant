#!/usr/bin/env bash

set -Eeuo pipefail

command -v yq jq &>/dev/null || {
  echo "yq and jq are required" >&2
  exit 1
}

declare mode="${1:?Must specify Host or Guest}"; mode="${mode,,}"; shift
if [[ "${mode}" != "host" && "${mode}" != "guest" ]]; then
  echo "Must specify Host or Guest; Got '${mode}'" >&2
  exit 1
fi
if [[ "${#}" -lt 1 ]]; then
  echo "Must Specify at least one Host Resource File" >&2
fi

case "${mode}" in
  "host" )
    yq -o json "$@" | 
      jq -s '{
        "all": {
          "hosts": (map(
            {
              "\(.metadata.name)": (
                {
                  "ansible_host": .spec.host,
                  "ansible_port": .spec.port,
                  "ansible_user": .spec.user,
                  "ansible_ssh_private_key_file": .spec.sshKey,
                } + .
              )
            }) | add
          )
        }
      }'
    ;;
  "guest" )
    yq -o json "$@" | 
      jq -s '{
        "all": {
          "hosts": (map(
            {
              "\(.metadata.name)": (
                {
                  "ansible_host": .spec.host,
                  "ansible_port": .spec.port,
                  "ansible_user": .spec.user,
                  "ansible_ssh_private_key_file": .spec.sshKey,
                }
              )
            }) | add
          )
        }
      }'
    ;;
esac |
  yq -o yaml -P
