#!/usr/bin/env bash

set -Eeuo pipefail

declare resource="${1:?Must specify a Resource}"; resource="${resource,,}"; shift
declare crud="${1:?Must specify Create, Update, or Delete}"; crud="${crud,,}"; shift

case "${resource}" in
  host )
    : "${HOST_INVENTORY:?Must specify a Host Inventory}"
    ansible-playbook \
      -i "${HOST_INVENTORY}" \
      -e "$(jq --arg crud "${crud}" -crn '{crud: $crud}')" \
      crud/host.yaml
    ;;
  image )
    : "${HOST_INVENTORY:?Must specify a Host Inventory}"
    declare host_filter="${1:?Must specify a Host Filter}"; shift
    declare manifest_file="${1:?Must specify a Resource Manifest}"; shift
    ansible-playbook \
      -i "${HOST_INVENTORY}" \
      -l "${host_filter}" \
      -e "$(yq -o json "${manifest_file}" | jq --arg crud "${crud}" -cr '. + {crud: $crud}')" \
      crud/image.yaml
    ;;
  guest )
    : "${INVENTORY:?Must specify an Inventory}"
    declare host_filter="${1:?Must specify a Host Filter}"; shift
    declare manifest_file="${1:?Must specify a Resource Manifest}"; shift
    ansible-playbook \
      -i "${INVENTORY}" \
      -l "${host_filter}" \
      -e "$(yq -o json "${manifest_file}" | jq --arg crud "${crud}" -cr '. + {crud: $crud}')" \
      crud/guest.yaml
    ;;
  * )
    echo "Unkown Resource '${resource}'" >&2
    exit 1
    ;;
esac
