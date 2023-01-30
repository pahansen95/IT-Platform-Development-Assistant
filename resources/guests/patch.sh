#!/usr/bin/env bash

set -Eeuo pipefail

gen_uuid() {
  declare _uuid
  uuid="$(
    uuidgen || "$(< /proc/sys/kernel/random/uuid)" || "$(python -c 'import uuid; print(uuid.uuid4())')"
  )"
  echo "${uuid,,}"
}

gen_mac(){
  declare _mac
  _mac="$(
    {
      printf '%s' '525400' # The QEMU OUI
      openssl rand -hex 3
    } | sed 's/\(..\)/\1:/g; s/.$//'
  )"
  echo "${_mac,,}"
}

command -v yq

declare tmp_file buffer_file; tmp_file="$(mktemp)"; buffer_file="$(mktemp)"
trap "rm -f '$tmp_file' '$buffer_file'" EXIT

while :; do
  : > "$tmp_file"
  : > "$buffer_file"
  unset name || true
  declare name="${1:-}"; shift
  if [[ -z "${name}" ]]; then
    break
  fi
  unset var_file || true
  declare var_file="./${name}.yaml"
  if [[ ! -f "$var_file" ]]; then
    echo "File not found: $var_file" >&2
    exit 1
  fi

  yq -o json "$var_file" > "$tmp_file"

  if ! jq -e '.metadata.uuid' "$tmp_file" > /dev/null; then
    jq -r --arg uuid "$(gen_uuid)" '.metadata.uuid = $uuid' "$tmp_file" > "$buffer_file"
    cat < "$buffer_file" > "$tmp_file"
  fi

  if ! jq -e '.spec.network.hwaddr' "$tmp_file" > /dev/null; then
    jq -r --arg mac "$(gen_mac)" '.spec.network.hwaddr = $mac' "$tmp_file" > "$buffer_file"
    cat < "$buffer_file" > "$tmp_file"
  fi

  declare -i vol_count; vol_count="$(jq -r '.spec.volumes | length' "$tmp_file")"
  if [[ "${vol_count}" -gt 0 ]]; then
    declare -i seq_stop; seq_stop="$((vol_count - 1))"
    mapfile -t < <(seq 0 "${seq_stop}")
    for i in "${MAPFILE[@]}"; do
      if ! jq -e --argjson i "${i}" '.spec.volumes[$i].uuid' "$tmp_file" > /dev/null; then
        jq -r \
          --argjson i "${i}" \
          --arg uuid "$(gen_uuid)" \
          '.spec.volumes[$i].uuid = $uuid' \
        "$tmp_file" > "$buffer_file"
        cat < "$buffer_file" > "$tmp_file"
      fi
    done
  fi

  yq -o yaml -P "$tmp_file" > "$var_file"
done
