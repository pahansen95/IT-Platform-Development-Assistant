#!/usr/bin/env bash
################
#### README ####
################
##
##  Use this file to quickly write well formed bash scripts.
##  User Script Logic is placed at the bottom of this template.
##
##  Quick Notes:
##    - Reference files relative to the script using "$CONTEXT". This is an absolute path of the parent directory.
##    - Basic state info found in the "$OS" & "$PROC" associative arrays.
##    - A Temporary Directory is provided at "$TEMP_DIR" & is cleaned up on exit.
##    - Leveled logging provided with the trace(), debug() info(), warn(), error(), success() & critical() functions.
##    - Logging is color coded by level.
##    - Exit with a critical level log using the panic() function.
##    - Switch between text & json logging with the --log-format parameter.
##    - Quick sanity checks with check_env() & check_dep().
##    - Assert Conditions & exit with an critical message with the assert() function.
##    - Pretty Print arrays the printa() functions.
##    - Print associative arrays, their keys & values using the printaa(), printaak(), printaav() functions respectively.
##    - Add custom flags & parameters in the parse_params() function
##    - Update the help message in the usage() function
##
##  This script is based off in part from https://gist.github.com/m-radzikowski/53e0b39e9a59a1518990e76c2bff8038
##  This script falls under the Apache License, Version 2.0
##
################
set -Eeu -o pipefail 
### Global Variables
declare -x CONTEXT UUID TEMP_DIR
CONTEXT="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)"
UUID="$({ uuidgen || uuid -v4 || cat /proc/sys/kernel/random/uuid || od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}' || echo -n 'cd259b1d-9164-d4aa-fdc5-39a6b894ee19'; } 2>/dev/null)"
TEMP_DIR="${TMPDIR:-/tmp}/${UUID}"; mkdir -p "$TEMP_DIR"; trap "rm -rf '${TEMP_DIR}'" EXIT ERR
declare -A OS PROC
OS["name"]="$(uname -s)"
OS["release"]="$(uname -r)"
OS["arch"]="$(uname -m)"
PROC["pid"]="$$"
PROC["ppid"]="$({ awk '/PPid/ { print $2 }' "/proc/$$/status" || ps -o ppid= "$$" || true; } 2>/dev/null)"
PROC["version"]="${BASH_VERSION}"
PROC["path"]="$(command -v bash)"
PROC["script"]="${BASH_SOURCE[0]}"
# For list of full colors see https://en.wikipedia.org/wiki/ANSI_escape_code
declare -a log_formats=( "text" "json" ) args=(); declare -A colors log_colors log_levels
colors["none"]='\033[0m'; colors["black"]='\033[0;30m'; colors["red"]='\033[0;31m'; colors["green"]='\033[0;32m'; colors["yellow"]='\033[0;33m'; colors["blue"]='\033[0;34m'; colors["magenta"]='\033[0;35m'; colors["cyan"]='\033[0;36m'; colors["white"]='\033[0;37m'
log_colors["trace"]="blue"; log_colors["debug"]="blue"; log_colors["info"]="cyan"; log_colors["warn"]="yellow"; log_colors["error"]="red"; log_colors["success"]="green"; log_colors["critical"]="red"
log_levels["trace"]="90"; log_levels["debug"]="80"; log_levels["info"]="70"; log_levels["warn"]="60"; log_levels["error"]="50"; log_levels["success"]="50"; log_levels["critical"]="40"; log_levels["quiet"]="0"
declare log_format="text" log_level="error"
printa() { trace "printa"; declare -n arr; arr="$1"; for val in "${arr[@]}"; do trace "val = '$val'"; declare suffix="'" prefix="'"; if [[ "$val" == "${arr[-1]}" ]]; then :; elif [[ "$val" == "${arr[-2]}" ]]; then suffix="' & "; else suffix="', "; fi; printf "%s%s%s" "$prefix" "$val" "$suffix"; unset suffix prefix; done; }
printaa() { trace "printaa"; declare -n asc_arr; asc_arr="$1"; declare -a keys; keys=("${!asc_arr[@]}"); for key in "${!asc_arr[@]}"; do declare suffix="'" prefix="'"; if [[ "$key" != "${keys[-1]}" ]]; then suffix="', "; fi; printf "%s%s=%s%s" "$prefix" "$key" "${asc_arr["$key"]}" "$suffix"; unset suffix prefix; done; }
printaak() { trace "printak"; declare -n asc_arr; asc_arr="$1"; declare -a keys; keys=("${!asc_arr[@]}"); printa keys; }
printaav() { trace "printav"; declare -n asc_arr; asc_arr="$1"; declare -a vals; vals=("${asc_arr[@]}"); printa vals; }
usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-x] [-l "error"] [--log-format "text"] --cleanup --docker-host --docker-socket

Quickly setup a IT Platform Development Environment. See README for full docs.

Available options:

-h, --help          Print this help and exit
--no-color          Disables Colored Logging
-x, --shell-trace   Print trace of the shell commands; WARNING! this can leak secrets
-l, --log-level     Sets the logging level; Valid Values are $(printaak "log_levels"); defaults to 'error'
--log-format        Sets the format of the log output; Valid Values are $(printa "log_formats"); defaults to 'text'; note that 'json' disables colors
--cleanup           Tells the script to destructively cleanup all deployed resources upon exit.
--docker-host       The name of the SSH Config entry that will be used to automatically expose the remote docker daemon locally.
--docker-socket     The path of the Unix Socket on the docker-host. Only used when --docker-host is also specified. Defaults to /var/run/docker.sock.
EOF
  exit
}
#### Logging ####
setup_colors() { if [[ -t 2 ]] && [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-}" != "dumb" ]]; then :; else for color in "${!colors[@]}"; do colors["$color"]=''; done; fi; }
compact_string() { declare -a lines; while read -r line; do lines+=('\n' "$line"); done <<<"$@"; printf "%s" "${lines[*]:1}"; }
msg() { echo >&2 -e "$*"; }
set_log_format() { for lformat in "${log_formats[@]}"; do if [[ "${1,,}" == "${lformat}" ]]; then debug "Set log format to $1"; log_format="${lformat}"; if [[ "${lformat}" == "json" ]]; then check_dep jq || panic "Please install jq to enable json formatted logs"; fi; return 0; fi; done; error "Unsupported Log Format $1"; return 1; }
set_log_level() { for level in "${!log_levels[@]}"; do if [[ "${1,,}" == "${level}" ]]; then log_level="${level}"; info "Log Level set to '$log_level'"; return 0; fi; done; msg "${colors[red]}$(date_prefix) [CRITICAL] unsupported log level '${1,,}'${colors[none]}"; return 1;}
log() { if [[ "${log_levels["$1"]}" -le "${log_levels["$log_level"]}" ]]; then if [[ "${log_format}" == "text" ]]; then msg "${colors["$2"]}$(date_prefix) [${1^^}] ${*:3}${colors[none]}"; elif [[ "${log_format}" == "json" ]]; then msg "$(jq -cn "{\"time\": \"$(date_prefix)\", \"level\": \"${1,,}\", \"message\": \$msg}" --arg msg "$(compact_string "${*:3}")")"; fi; fi; } # $1 == level; $2 == Color; $3... == Message
date_prefix() { date -Ins 2>/dev/null || date -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || ps -p "$$" -o "etime=" 2>/dev/null; }
trace()     { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
debug()     { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
info()      { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
warn()      { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
error()     { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
success()   { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
critical()  { log "${FUNCNAME[0],,}" "${log_colors[${FUNCNAME[0],,}]}" "$*"; }
panic()     { critical "$*"; exit 255; } # default exit status 255
assert()    { if ! eval "$1"; then panic "${2:-"Assertion Failed for '$1'"}"; fi; }
#### Helpers ###
check_env() { declare env_error="false"; for var in "$@"; do trace "Checking for ${var} in environment"; if [[ -z "${!var:-}" ]]; then env_error="true"; echo "$var"; warn "$var not found in environment"; else debug "${var} found in environment"; fi; done; if [[ "$env_error" == "true" ]]; then trace "return 1"; return 1; else trace "return 0"; return 0; fi; }
check_dep() { declare dep_error="false"; for dep in "$@"; do trace "Checking for ${dep} in environment"; if ! which "$dep" 2>/dev/null 1>&2; then dep_error="true"; echo "$dep"; warn "$dep not found in path"; else debug "$dep found in path"; fi; done; if [[ "$dep_error" == "true" ]]; then trace "return 1"; return 1; else trace "return 0"; return 0; fi; }
parse_params() {
  # Global User Variables & Default Values
  declare -g \
    param_docker_host \
    param_cleanup='false' \
    param_docker_socket='/var/run/docker.sock'

  while :; do
    # Just parse paramter list here; don't execute logic until after logging is set
    case "${1:-}" in
    ### Script Parameters ###
    -h | --help) usage ;;
    -x | --shell-trace) set -x ;;
    --no-color) NO_COLOR=1 ;;
    -l | --log-level)
      log_level="${2:-}"
      shift
      ;;
    --log-format)
      log_format="${2:-}"
      shift
      ;;
    ### User Parameters ###
    # Flags
    --cleanup) param_cleanup="true" ;;
    # Key Value Pairs
    --docker-host)
      param_docker_host="${2:?"--docker-host specified but no value given"}"
      shift
      ;;
    --docker-socket)
      param_docker_socket="${2:?"--docker-socket specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done
  # Setup Logging
  set_log_format "$log_format" || panic "invalid log format"
  set_log_level "$log_level"  || panic "invalid log level"
  # Set Args
  args+=("$@")
  # Global User Variable Parsing Logic
  # ...
  return 0
}
parse_params "$@"
setup_colors
declare runtime_info script_info
runtime_info="$(cat - <<EOF
Runtime Info:
  Bash ............................ $(printaa "PROC")
  Operating System ................ $(printaa "OS")
EOF
)"
script_info="$(cat - <<EOF
Script Info:
  Subcommand ...................... ${args[*]:0:1}
  Parameters:
    --cleanup ..................... ${param_cleanup}
    --docker-host ................. ${param_docker_host:-}
    --docker-socket ............... ${param_docker_socket:-}
  Arguments ....................... ${args[*]:1}
EOF
)"
info "$runtime_info"
info "$script_info"

############################
#### SCRIPT LOGIC BELOW ####
############################

### Variable & Env Setup ###

declare -A \
  subprocs \
  containers

declare \
  xo_cli_cntr \
  xo_addr \
  iso_share_cntr \
  iso_share_addr \
  xenorch_url='http://localhost' \
  xenorch_default_admin='admin@admin.net' \
  xenorch_default_pswd='admin' \
  remote_docker_ssh_host="${param_docker_host:-}" \
  remote_docker_socket="${param_docker_socket:-"/var/run/docker.sock"}"

check_env \
  XCP_NODE_USER \
  XCP_NODE_PASSWORD \
  XCP_NODE_ADDR \
  XOA_ADMIN_EMAIL \
  XOA_ADMIN_PASSWORD

check_dep \
  jq \
  ssh \
  git \
  docker \
  curl \
  terraform
    
### Functions ###

wait_to_exit() {
  trap cleanup 0
  declare rc
  rc="${1:-0}"
  [[ "${rc}" -ne 0 ]] && critical "Exiting w/ Return Code ${rc}"
  declare \
    user_regex='^exit$'
  while : ; do
    read -r -p "$(printf '%s\n\t> ' 'Type exit & press return to exit & cleanup this script')" user_cmd
    [[ "${user_cmd,,}" =~ $user_regex ]] && break
  done
  exit "${rc}"
}

cleanup() {
  info "Cleaning Up"
  info "Terminating Sub-Processes"
  for subproc_pid in "${subprocs[@]}"; do
    debug "Terminating '${subproc_pid}'"
    kill -15 "$subproc_pid" || kill -9 "$subproc_pid" || error "couldn't stop proc '${subproc_pid}'"
  done
  if [[ "${param_cleanup}" == 'true' ]]; then
    info "--cleanup specified; terminating containers"
    for cntr_name in "${!containers[@]}"; do
      # TODO Graceful stops
      debug "Terminating '${cntr_name}'"
      docker rm -f "${containers[cntr_name]}"
    done
  else
    debug "--cleanup not specified; skip terminating containers"
  fi
}

setup_docker() {
  # 1 - remote host
  # 2 (optional) - remote Unix socket
  declare \
    remote_docker_ssh_entry \
    remote_docker_unix_sock \
    local_docker_bind_addr="127.0.0.1" \
    local_docker_tcp_port="2375"

  declare -x \
    DOCKER_HOST="tcp://${local_docker_bind_addr}:${local_docker_tcp_port}"

  remote_docker_ssh_entry="${1:?Must Specify an SSH Config Entry for the Remote Docker Host}"
  remote_docker_unix_sock="${2:-/var/run/docker.sock}"

  info "Setup Connection to Remote Docker Host"

  # Port Forward Remote Docker Unix Socket
  ssh \
    -N -T \
    -L "${local_docker_bind_addr}:${local_docker_tcp_port}:${remote_docker_unix_sock}" \
    "${remote_docker_ssh_entry}" &
  subprocs[docker_socket]="$(jobs -p '%+')"
  
  info "Waiting for Remote Docker Host..."
  until docker ps -q 2>/dev/null; do
    debug "Remote Docker Host not ready"
    sleep 1
  done

  success "Remote Docker Host Connection Setup"
  return 0
}

get_docker_host_ip() {
  # 1 - the name ref to set
  # 2 (optional) - the ssh entry for the remote docker host
  declare -n \
    var_ref
  
  declare \
    remote_host

  var_ref="${1:-"Must Specify a variable name to assign the docker host address to"}"
  remote_host="${2:-}"

  if [[ -n "${remote_host}" ]]; then
    declare \
      remote_default_eth \
      remote_default_ip
    
    remote_default_eth="$(
      ssh "${remote_host}" \
        "ip route show | awk '/^default/ {print \$5}' | head -n 1"
    )"
    remote_default_ip="$(
      ssh "${remote_host}" \
        "ip addr show ${remote_default_eth} | awk '/inet / {print \$2}'"
    )"
    remote_default_ip="${remote_default_ip%/*}"
    debug "default_eth=${remote_default_eth}"
    debug "default_ip=${remote_default_ip}"
    
    var_ref="${remote_default_ip}"
  else
    declare \
      default_eth \
      default_ip
    
    default_eth="$(ip route show | awk '/^default/ {print $5}' | head -n 1)"
    default_ip="$(ip addr show "${default_eth}" | awk '/inet / {print $2}')"
    default_ip="${default_ip%/*}"
    debug "default_eth=${default_eth}"
    debug "default_ip=${default_ip}"

    var_ref="${default_ip:-127.0.0.1}"
  fi
  return 0
}

docker_build() {
  # 1 - folder under docker/ to build
  # 2 (optional) - the fully qualified container image name + tag
  declare \
    target_folder \
    docker_context \
    container_image_tag

  target_folder="${1:-Must specify a docker sub-project to build}"
  docker_context="${CONTEXT}/docker/${target_folder}"
  container_image_tag="${2:-"peterhansen.io/xcp-ng/${target_folder}:latest"}"

  if [[ ! -d "${docker_context}" || ! -f "${docker_context}/build.sh" ]]; then
    critical "couldn't find dir '${docker_context}' or file '${docker_context}/build.sh'"
    return 1
  fi

  source "${docker_context}/build.sh" \
    "${docker_context}" \
    "${container_image_tag}"

  printf "%s" "${container_image_tag}"

  return 0
}

docker_run() {
  ###
  # optional parameters:
  #   --tag - the fully qualified container image tag 
  #   --name - the Docker container instance name
  #   --tag-var - the variable to store the fully qualified container image tag 
  #   --name-var - the variable to store the Docker container instance name
  #
  # positional args
  #   1 - folder under docker/ to run
  #
  ###

  while :; do
    case "${1:-}" in
    --name)
      declare param_name="${2:?"--name specified but no value given"}"
      shift
      ;;
    --tag)
      declare param_tag="${2:?"--tag specified but no value given"}"
      shift
      ;;
    --name-var)
      declare -n param_name_var="${2:?"--name-var specified but no value given"}"
      shift
      ;;
    --tag-var)
      declare -n param_tag_var="${2:?"--tag-var specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to docker_run: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")

  declare \
    target_folder \
    docker_context \
    container_image_tag \
    container_instance_name

  target_folder="${args[0]:-Must specify a docker sub-project to build}"
  docker_context="${CONTEXT}/docker/${target_folder}"
  container_image_tag="${param_tag:-"peterhansen.io/xcp-ng/${target_folder}:latest"}"
  container_instance_name="${param_name:-"${target_folder}"}"
  [[ -R 'param_name_var' ]] && param_name_var="${container_instance_name}"
  [[ -R 'param_tag_var' ]] && param_tag_var="${container_image_tag}"

  if [[ ! -d "${docker_context}" || ! -f "${docker_context}/run.sh" ]]; then
    critical "couldn't find dir '${docker_context}' or file '${docker_context}/run.sh'"
    return 1
  fi

  source "${docker_context}/run.sh" \
    "${docker_context}" \
    "${container_image_tag}" \
    "${container_instance_name}"

  return 0
}

xo_get_objects() {
  ###
  # optional parameters:
  #   --cntr - the Docker container instance name
  #   --obj-var - The Variable to store the filtered objects in. If not specified it prints to stdout instead.
  #   --include - Object types to include. May be specified multiple times 
  #   --exclude - Object types to exclude. May be specified multiple times 
  #
  # positional args
  #
  ###
  declare -a \
    include_filter=() \
    exclude_filter=()
  while :; do
    debug "${1:-} ${2:-}"
    case "${1:-}" in
    --cntr)
      declare param_cntr="${2:?"--cntr specified but no value given"}"
      shift
      ;;
    --include)
      include_filter+=( "${2:?"--include specified but no value given"}" )
      shift
      ;;
    --exclude)
      exclude_filter+=( "${2:?"--exclude specified but no value given"}" )
      shift
      ;;
    --obj-var)
      declare param_obj_var="${2:?"--obj-var specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to xo_get_objects: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")

  debug "param_cntr=${param_cntr:-}"
  debug "param_obj_var=${param_obj_var:-}"
  debug "include_filter=${include_filter[*]:-}"
  debug "exclude_filter=${param_cntr[*]:-}"
  debug "args=${args[*]:-}"

  declare xo_cli
  if [[ -n "${param_cntr}" ]]; then
    xo_cli="docker exec ${param_cntr}"
  fi
  xo_cli="${xo_cli:-} xo-cli"

  # By Default Match all if no other filters are provided
  [[ "${#include_filter[@]}" -eq 0 ]] && include_filter+=( '^.+$' )

  declare \
    objects_json \
    include_json \
    exclude_json='[]'

  include_json="$({
    printf '%s\n' "${include_filter[@]}" |
    jq -Rn '[inputs]'
  })"
  if [[ "${#exclude_filter[@]}" -gt 0 ]]; then
    exclude_json="$({
      printf '%s\n' "${exclude_filter[@]}" |
      jq -Rn '[inputs]'
    })"
  fi

  trace "include_json=${include_json}"
  trace "exclude_json=${exclude_json:-}"
  declare \
    all_objects_json \
    retry_count=0
  info "Retry up to 3 times to get a valid response from XO"
  all_objects_json="$(${xo_cli} --list-objects)"
  until echo "${all_objects_json:-}" | jq -e . 1>/dev/null 2>&1; do
    if [[ "${retry_count}" -gt 3 ]]; then
      error "Error Parsing XO Object List"
      return 1
    fi
    debug "Invalid response returned; trying again"
    sleep 2
    all_objects_json="$(${xo_cli} --list-objects)"
  done

  trace "${all_objects_json}"
  objects_json="$({
    echo "${all_objects_json}" |
    jq \
      --argjson includes "${include_json}" \
      '
        [ 
          .[] as $obj | $includes[] as $in_filter | 
          $obj.type | if test( $in_filter ) then $obj else empty end
        ]
      ' |
    jq \
      --argjson excludes "${exclude_json}" \
      '
        [
          .[] as $obj |
          [
            $excludes[] as $ex_filter | if $obj.type | test( $ex_filter ) then true else false end  
          ] as $test_results |
          if $test_results | any then empty else $obj end
        ]
      '
  })"
  trace "objects_json=${objects_json:-}"

  if [[ -n "${param_obj_var:-}" ]]; then
    debug "Assigning to Variable Reference"
    declare -n \
      obj_var="${param_obj_var}"
    obj_var="${objects_json}"
  else
    debug "Printing to stdout"
    echo "${objects_json}"
  fi

  return 0
}

xo_session() {  
  ###
  # optional parameters:
  #   --cntr - the Docker container instance name
  #   --url - the fully qualified container image tag 
  #
  # positional args
  #   user - the variable to store the fully qualified container image tag 
  #   pswd - the variable to store the Docker container instance name
  ###

  while :; do
    case "${1:-}" in
    --cntr)
      declare param_cntr="${2:?"--cntr specified but no value given"}"
      shift
      ;;
    --url)
      declare param_url="${2:?"--url specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to xo_session: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")
  declare xo_cli
  if [[ -n "${param_cntr}" ]]; then
    xo_cli="docker exec ${param_cntr}"
  fi
  xo_cli="${xo_cli:-} xo-cli"

  declare \
    xo_url \
    xo_username \
    xo_password

  xo_url="${param_url:-"https://localhost:8443"}"
  xo_username="${args[0]:?"Must Specify a Username for xo_session"}"
  xo_password="${args[1]:?"Must Specify a Password for xo_session"}"
  
  debug "xo_cli=${xo_cli:-}"
  debug "xo_url=${xo_url:-}"
  debug "xo_username=${xo_username:-}"
  debug "xo_password=${xo_password:-}"

  # Attempt to unregister the session first
  debug "End existing session ignoring errors"
  ${xo_cli} --unregister 2>/dev/null || true

  # Start a new session
  debug "Start a new session"
  ${xo_cli} \
    --register \
    --allowUnauthorized \
    "${xo_url}" \
    "${xo_username}" \
    "${xo_password}"

  return 0
}

xo_user() {
  ###
  # optional parameters:
  #   --state - the state of the user; present or absent. defaults to present.
  #   --perms - the users permissions
  #   --pswd - the users password
  #
  # positional args
  #   email - the users identifying email
  ###

  while :; do
    case "${1:-}" in
    --cntr)
      declare param_cntr="${2:?"--cntr specified but no value given"}"
      shift
      ;;
    --state)
      declare param_state="${2,,:?"--state specified but no value given"}"
      shift
      ;;
    --perms)
      declare param_perms="${2:?"--perms specified but no value given"}"
      shift
      ;;
    --pswd)
      declare param_pswd="${2:?"--pswd specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to xo_user: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")
  declare xo_cli
  if [[ -n "${param_cntr}" ]]; then
    xo_cli="docker exec ${param_cntr}"
  fi
  xo_cli="${xo_cli:-} xo-cli"

  declare \
    user_id \
    user_email \
    user_password \
    user_permissions \
    user_state

  user_email="${args[0]:?"Must specify a user's email for xo_user"}"
  user_password="${param_pswd:-}"
  user_permissions="${param_perms:-"admin"}"
  user_state="${param_state:-"present"}"
  
  case "${user_state}" in 
  "present")
    # Check for user
    {
      declare user_list_json
      user_list_json="$(${xo_cli} user.getAll)"
      user_id="$({
          echo "${user_list_json}" |
          jq -e -r \
            --arg email "${user_email}" \
            '.[] | select(.email == $email) | .id // empty'
      })"
    }
    # Create it they don't exist
    if [[ -z "${user_id}" ]]; then
      ${xo_cli} user.create \
        email="${user_email}" \
        password="${user_password:?"Must Specify Password for '${user_email}' when creating them for the first time"}" \
        permission="${user_permissions}"
    else
      debug "user '${user_email}' already exists; skipping create call"
    fi
    # Set properties as passed
    :
    success "User '${user_email}' is present"
    ;;
  "absent")
    # Check for user
    {
      declare user_list_json
      user_list_json="$(${xo_cli} user.getAll)"
      user_id="$(
        {
          echo "${user_list_json}" |
          jq -e -r \
            --arg email "${user_email}" \
            '.[] | select(.email == $email) | .id // empty'
        }
      )"
    }
    # Delete User if they exist
    if [[ -n "${user_id}" ]]; then
      ${xo_cli} user.delete \
        id="${user_id}"
    else
      debug "user '${user_email}' doesn't exist; skip delete call"
    fi
    :
    success "User '${user_email}' is absent"
    ;;
  *)
    error "${user_state} is not a valid state for xo_user"
    return 1
    ;;
  esac

  return 0
}

xo_node() {
  ###
  # optional parameters:
  #   --cntr - the Docker container instance name
  #   --state - the state of the user; present or absent. defaults to present.
  #   --user - the remote node's login user
  #   --pswd - the remote node's login password
  #
  # positional args
  #   Node Address - the node's ip address or FQDN
  ###

  while :; do
    case "${1:-}" in
    --cntr)
      declare param_cntr="${2:?"--cntr specified but no value given"}"
      shift
      ;;
    --state)
      declare param_state="${2,,:?"--state specified but no value given"}"
      shift
      ;;
    --user)
      declare param_user="${2:?"--user specified but no value given"}"
      shift
      ;;
    --pswd)
      declare param_pswd="${2:?"--pswd specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to xo_node: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")
  declare xo_cli
  if [[ -n "${param_cntr}" ]]; then
    xo_cli="docker exec ${param_cntr}"
  fi
  xo_cli="${xo_cli:-} xo-cli"

  declare \
    xcp_node_state \
    xcp_node_id \
    xcp_node_address \
    xcp_node_login_username \
    xcp_node_login_password

  xcp_node_state="${param_state:-"present"}"
  xcp_node_address="${args[0]:?"Must Specify the Nodes address for xo_node"}"

  case "${xcp_node_state}" in 
  "present")
    # Check for node
    {
      declare node_list_json
      node_list_json="$(${xo_cli} server.getAll)"
      xcp_node_id="$(
        {
          echo "${node_list_json}" |
          jq -e -r \
            --arg node_addr "${xcp_node_address}" \
            '.[] | select(.host == $node_addr) | .id // empty'
        }
      )"
    }
    # Add the node if its not already present
    if [[ -z "${xcp_node_id}" ]]; then
      xcp_node_login_username="${param_user:?"Must specify a username when adding a node for the first time"}"
      xcp_node_login_password="${param_pswd:?"Must specify a password when adding a node for the first time"}"
      ${xo_cli} server.add \
        host="${xcp_node_address}" \
        username="${xcp_node_login_username}" \
        password="${xcp_node_login_password}" \
        autoConnect=true \
        allowUnauthorized=true
    else
      debug "node '${xcp_node_address}' already exists; skipping server.add call"
    fi
    # Set labels as passed
    :
    success "Node '${xcp_node_address}' is present"
    ;;
  "absent")
    # Check for node
    {
      declare node_list_json
      node_list_json="$(${xo_cli} server.getAll)"
      xcp_node_id="$(
        {
          echo "${node_list_json}" |
          jq -e -r \
            --arg node_addr "${xcp_node_address}" \
            '.[] | select(.host == $node_addr) | .id // empty'
        }
      )"
    }
    # Remove Node if it exists
    if [[ -n "${xcp_node_id}" ]]; then
      ${xo_cli} server.remove \
        id="${xcp_node_id}"
    else
      debug "Node '${xcp_node_address}' doesn't exist; skip server.remove call"
    fi
    :
    success "Node '${xcp_node_address}' is absent"
    ;;
  *)
    error "${xcp_node_state} is not a valid state for xo_node"
    return 1
    ;;
  esac
  
  return 0
}

xo_sr() {
  ###
  # optional parameters:
  #   --cntr - the Docker container instance name
  #   --state - the state of the user; present or absent. defaults to present.
  #   --type - the type of Storage Repository. ie. ISO, LVM, ZFS, etc...
  #   --host - the Node in the Pool the SR is configured for
  #   --src - the source of the SR in URL format. ex. A Samba ISO looks like smb://192.168.0.24/share
  #
  # positional args
  #   SR Name - The unique name of the Storage Repository
  ###

  while :; do
    case "${1:-}" in
    --cntr)
      declare param_cntr="${2:?"--cntr specified but no value given"}"
      shift
      ;;
    --state)
      declare param_state="${2,,:?"--state specified but no value given"}"
      shift
      ;;
    --type)
      declare param_type="${2:?"--type specified but no value given"}"
      shift
      ;;
    --host)
      declare param_host="${2:?"--host specified but no value given"}"
      shift
      ;;
    --src)
      declare param_src="${2:?"--src specified but no value given"}"
      shift
      ;;
    -?*) panic "Unknown option supplied to xo_sr: $1" ;;
    *) break ;;
    esac
    shift
  done
  local -a args=("$@")
  declare xo_cli
  if [[ -n "${param_cntr}" ]]; then
    xo_cli="docker exec ${param_cntr}"
  fi
  xo_cli="${xo_cli:-} xo-cli"

  declare \
    sr_state \
    sr_type \
    sr_host_id \
    sr_source \
    sr_name

  # Retrieve the Host ID
  if [[ -n "${param_host}" ]]; then
    declare node_list_json node_obj_json
    declare -a xo_get_params
    [[ -n "${param_cntr}" ]] && xo_get_params+=( "--cntr" "${param_cntr}" )
    xo_get_params+=( "--obj-var" "node_list_json" )
    xo_get_params+=( "--include" 'host' )
    xo_get_objects "${xo_get_params[@]}"
    unset xo_get_params
    node_obj_json="$({
      echo "${node_list_json}" |
      jq -e \
        --arg node_addr "${param_host}" \
        '.[] | select(.address == $node_addr) // empty'
    })"
    sr_host_id="$({
      echo "${node_obj_json}" |
      jq -r \
        '.id'
    })"
    trace "node_list_json=${node_list_json}"
    trace "node_obj_json=${node_obj_json}"
  fi
  sr_state="${param_state}"
  sr_name="${args[0]:?"Must Specify the Storage Repository's name at a minimum."}"

  case "${sr_state}" in 
  "present")
    # Check for SR
    {
      declare sr_list_json sr_obj_json
      declare -a xo_get_params
      [[ -n "${param_cntr}" ]] && xo_get_params+=( "--cntr" "${param_cntr}" )
      xo_get_params+=( "--obj-var" "sr_list_json" )
      xo_get_params+=( "--include" 'SR' )
      xo_get_objects "${xo_get_params[@]}"

      sr_obj_json="$({
          echo "${sr_list_json}" |
          jq -e \
            --arg name_label "${sr_name}" \
            '.[] | select(.name_label == $name_label) // empty'
      })"
    }
    # Create the SR if its not already present
    if [[ -z "${sr_obj_json}" ]]; then
      sr_type="${param_type:?"must specify a Storage Repository type when creating one for the first time"}"

      declare \
        uri_scheme \
        uri_addr \
        uri_path
            
      case "${sr_type,,}" in
      iso)
        # Underlying API Source Here -> https://github.com/vatesfr/xen-orchestra/blob/15d06c591ef4eafda199eb516c016a198420764f/packages/xo-server/src/api/sr.mjs#L126
        # Parse the URL
        sr_source="${param_src:?"must specify a source URL when creating an ISO Storage Repository for the first time"}"
        uri_scheme="${sr_source%%://*}"
        uri_addr="${sr_source#*://}"; uri_addr="${uri_addr%%/*}"
        uri_path="${sr_source#"${uri_scheme}://${uri_addr}"}"
        if [[ -z "${uri_scheme}" || -z "${uri_addr}" || -z "${uri_path}" ]]; then
          error "Invalid Source URL for SR type ISO: '${sr_source}'"
          return 1
        fi
        debug "sr_source=${sr_source:-}"
        debug "uri_scheme=${uri_scheme:-}"
        debug "uri_addr=${uri_addr:-}"
        debug "uri_path=${uri_path:-}"
        case "${uri_scheme,,}" in
        smb | samba)
          # Underlying API Source Here -> https://github.com/vatesfr/xen-orchestra/blob/15d06c591ef4eafda199eb516c016a198420764f/packages/xo-server/src/api/sr.mjs#L132
          info "Creating Samba based ISO Storage Repository"
          : "${param_host:?"Must Specify a hostname when creating a Storage Repository for the first time"}"
          trace "host=${sr_host_id:-}"
          trace "nameLabel=${sr_name:-}"
          trace "nameDescription=${sr_name:-}"
          trace "path=//${uri_addr:-}${uri_path:-}"
          trace "type=smb"
          ${xo_cli} sr.createIso \
            host="${sr_host_id:?"Couldn't find host ${param_host}"}" \
            nameLabel="${sr_name}" \
            nameDescription="${sr_name}" \
            path="//${uri_addr}${uri_path}" \
            type="smb" \
            user="user" \
            password="password"
          ;;
        *)
          error "ISO Share of type '${uri_scheme}' is not implemented"
          return 1
          ;;
        esac
        ;;
      *)
        error "Storage Repository Type '${sr_type}' is not implemented"
        return 1
        ;;
      esac
    else
      debug "SR '${sr_name}' already exists; skipping sr.create* call"
    fi
    success "SR '${sr_name}' is present"
    ;;
  "absent")
    # Check for SR
    {
      declare sr_list_json sr_obj_json
      declare -a xo_get_params
      [[ -n "${param_cntr}" ]] && xo_get_params+=( "--cntr" "${param_cntr}" )
      xo_get_params+=( "--obj-var" "sr_list_json" )
      xo_get_params+=( "--include" "'SR'" )
      xo_get_objects "${xo_get_params[@]}"

      sr_obj_json="$({
          echo "${sr_list_json}" |
          jq -e \
            --arg name_label "${sr_name}" \
            '.[] | select(.name_label == $name_label and .) // empty'
      })"
    }
    # Delete the SR if its present
    if [[ -n "${sr_obj_json}" ]]; then
      ${xo_cli} sr.destroy \
        id="$(echo "${sr_obj_json}" | jq -r '.id')"
    else
      debug "SR '${sr_name}' doesn't exist; skipping sr.destroy call"
    fi
    success "SR '${sr_name}' is absent"
    ;;
  esac

  return 0
}

### Setup Docker ###
info "Setup Docker"
if ! docker ps -q 2>/dev/null; then
  if [[ -z "${remote_docker_ssh_host:-}" || -z "${remote_docker_socket:-}" ]]; then
    panic "Docker Daemon cannot be reached. Either make it available to the host or specify a remote SSH Host to port forward to."
  fi
  setup_docker \
    "${remote_docker_ssh_host}" \
    "${remote_docker_socket}" \
  || wait_to_exit "$?"
fi

### Build the Services ###
info "Build the Services"
{
  docker_build "os-imgs"
  docker_build "xoa"
} || wait_to_exit "$?"

### Run the Services ###
info "Run the Services"
{
  docker_run \
    --name-var iso_share_cntr \
    "os-imgs"
  containers["iso_share"]="${iso_share_cntr}"
  get_docker_host_ip \
    iso_share_addr \
    "${remote_docker_ssh_host:-}"
  : "${iso_share_addr:?"Couldn't get the IP address of the Docker Host"}"
  xo_addr="${iso_share_addr}"
  docker_run \
    --name-var xo_cli_cntr \
    "xoa"
  containers["xo_cli"]="${xo_cli_cntr}"
} || wait_to_exit "$?"

### Setup Xen Orchestra & Configure the Host Pool ###
info "Setup Xen Orchestra & Configure the Host Pool"
# Start a Session w/ the Default Admin
info "Start a Session w/ the Default Admin"
xo_session --cntr "${xo_cli_cntr}" \
  --url "${xenorch_url}" \
  "${xenorch_default_admin}" \
  "${xenorch_default_pswd}" \
|| wait_to_exit "$?"

# Add the User Admin
info "Add the User Admin"
xo_user --cntr "${xo_cli_cntr}" \
  --state 'present' \
  --perms 'admin' \
  --pswd "${XOA_ADMIN_PASSWORD}" \
  "${XOA_ADMIN_EMAIL}" \
|| wait_to_exit "$?"

# Start a new session w/ the User Admin
info "Start a new session w/ the User Admin"
xo_session --cntr "${xo_cli_cntr}" \
  --url "${xenorch_url}" \
  "${XOA_ADMIN_EMAIL}" \
  "${XOA_ADMIN_PASSWORD}" \
|| wait_to_exit "$?"

# Remove the Default Admin
info "Remove the Default Admin"
xo_user --cntr "${xo_cli_cntr}" \
  --state 'absent' \
  "${xenorch_default_admin}" \
|| wait_to_exit "$?"

# Add the Node
info "Add the Node"
xo_node --cntr "${xo_cli_cntr}" \
  --state "present" \
  --user "${XCP_NODE_USER}" \
  --pswd "${XCP_NODE_PASSWORD}" \
  "${XCP_NODE_ADDR}" \
|| wait_to_exit "$?"

# Add the OS Image Share as an ISO SR
info "Add the OS Image Share as an ISO SR"
xo_sr --cntr "${xo_cli_cntr}" \
  --state "present" \
  --type "iso" \
  --host "${XCP_NODE_ADDR}" \
  --src "smb://${iso_share_addr}/os-imgs" \
  "os-imgs" \
|| wait_to_exit "$?"

### Generate Terraform Config Template ###
info "Generate Terraform Config Template"
trace "$(tee "./xo-template.tf" <<EoC
terraform {
  required_providers {
    xenorchestra = {
      source = "terra-farm/xenorchestra"
      version = "0.23.0"
    }
  }
}

provider "xenorchestra" {
  url       = "wss://${xo_addr}"
  username  = "${XOA_ADMIN_EMAIL}"
  password  = "${XOA_ADMIN_PASSWORD}"
}
EoC
)"

### Print Success Messages ###
success "$(tee "./setup-results.txt" <<EoF
The Setup Script has complete succesfully.

===================
=== XCP-ng Node ===
===================
Addr: ${XCP_NODE_ADDR}
SSH Conf Entry: xcp
SSH Priv Key: ~/.ssh/xcp-ng
SSH Pub Key: ~/.ssh/xcp-ng.pub

======================
=== OS Image Share ===
======================
Proto: Samba
Conn: //${iso_share_addr}/os-imgs
User: username
Pass: password

===========================
=== Xen Orchestra WebUI ===
===========================
Proto: HTTPS
Conn: https://${xo_addr}:8443/
User: ${XOA_ADMIN_EMAIL}
Pass: REDACTED (Set by env var XOA_ADMIN_PASSWORD)

=================================
=== Terraform Config Template ===
=================================
Path: $PWD/xo-template.tf

=====================
=== Setup Results ===
=====================
Path: $PWD/setup-results.txt

EoF
)"

wait_to_exit 0
