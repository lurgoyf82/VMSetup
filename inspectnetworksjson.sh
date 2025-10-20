#!/bin/bash
# Aggregate network inspection data into an array of JSON objects for Raffo Setup.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./inspectnetwork.sh
source "$SCRIPT_DIR/inspectnetwork.sh"

#
# Array holding JSON snippets describing each detected network connection.
#
connections=()

# json_escape VALUE
# -----------------
# Emit VALUE with JSON special characters escaped so that it can be safely
# embedded inside string literals when constructing JSON manually.
json_escape() {
  local value="$1"
  # Escape backslashes first, then quotes and control characters.
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

# json_array_from_string DATA
# ---------------------------
# Convert a newline separated DATA string into a JSON array. Empty DATA
# becomes an empty array. Each line is JSON-escaped to preserve formatting.
json_array_from_string() {
  local data="$1"
  local first=1
  printf '['
  while IFS= read -r line; do
    if (( first )); then
      first=0
    else
      printf ','
    fi
    printf '"%s"' "$(json_escape "$line")"
  done < <(printf '%s' "$data")
  printf ']'
}

# has_default_route FAMILY IFACE
# ------------------------------
# Return success when IFACE participates in a default route for the requested
# address FAMILY ("4" for IPv4, "6" for IPv6).
has_default_route() {
  local family="$1"
  local iface="$2"
  local route

  if [[ "$family" == "4" ]]; then
    for route in "${NETWORK_DEFAULT_ROUTES_IPV4[@]}"; do
      if [[ "$route" == *" dev $iface "* || "$route" == *" dev $iface" ]]; then
        return 0
      fi
    done
  else
    for route in "${NETWORK_DEFAULT_ROUTES_IPV6[@]}"; do
      if [[ "$route" == *" dev $iface "* || "$route" == *" dev $iface" ]]; then
        return 0
      fi
    done
  fi

  return 1
}

# build_connection_json IFACE
# ---------------------------
# Generate a JSON object representing the collected details for IFACE.
build_connection_json() {
  local iface="$1"
  local state="${NETWORK_INTERFACE_STATE[$iface]:-}"
  local mtu="${NETWORK_INTERFACE_MTU[$iface]:-}"
  local mac="${NETWORK_INTERFACE_MAC[$iface]:-}"
  local ipv4_addrs="${NETWORK_INTERFACE_IPV4_ADDRS[$iface]:-}"
  local ipv6_addrs="${NETWORK_INTERFACE_IPV6_ADDRS[$iface]:-}"
  local ipv4_routes="${NETWORK_INTERFACE_IPV4_ROUTES[$iface]:-}"
  local ipv6_routes="${NETWORK_INTERFACE_IPV6_ROUTES[$iface]:-}"
  local default_v4="false"
  local default_v6="false"
  local ipv4_json ipv6_json routes4_json routes6_json

  ipv4_json=$(json_array_from_string "$ipv4_addrs")
  ipv6_json=$(json_array_from_string "$ipv6_addrs")
  routes4_json=$(json_array_from_string "$ipv4_routes")
  routes6_json=$(json_array_from_string "$ipv6_routes")

  if has_default_route "4" "$iface"; then
    default_v4="true"
  fi
  if has_default_route "6" "$iface"; then
    default_v6="true"
  fi

  printf '{'
  printf '"name":"%s",' "$(json_escape "$iface")"

  if [[ -n "$state" ]]; then
    printf '"state":"%s",' "$(json_escape "$state")"
  else
    printf '"state":null,'
  fi

  if [[ -n "$mtu" ]]; then
    printf '"mtu":%s,' "$mtu"
  else
    printf '"mtu":null,'
  fi

  if [[ -n "$mac" ]]; then
    printf '"mac":"%s",' "$(json_escape "$mac")"
  else
    printf '"mac":null,'
  fi

  printf '"ipv4_addresses":%s,' "$ipv4_json"
  printf '"ipv6_addresses":%s,' "$ipv6_json"
  printf '"ipv4_routes":%s,' "$routes4_json"
  printf '"ipv6_routes":%s,' "$routes6_json"
  printf '"default_ipv4":%s,' "$default_v4"
  printf '"default_ipv6":%s' "$default_v6"
  printf '}'
}

# generate_connections
# --------------------
# Populate the global connections array with a JSON object for every detected
# network interface. Works with indexed or associative maps; falls back to keys
# of other per-interface maps.
generate_connections() {
  connections=()

  local -a iface_list=()
  local decl

  # Detect if NETWORK_INTERFACES is associative or indexed
  if decl=$(declare -p NETWORK_INTERFACES 2>/dev/null); then
    if [[ "$decl" == declare\ -A* ]]; then
      local k
      for k in "${!NETWORK_INTERFACES[@]}"; do
        [[ -n "$k" ]] && iface_list+=("$k")
      done
    else
      local v
      for v in "${NETWORK_INTERFACES[@]}"; do
        [[ -n "$v" ]] && iface_list+=("$v")
      done
    fi
  fi

  # Fallback: union of keys from known per-interface maps
  if (( ${#iface_list[@]} == 0 )); then
    declare -A seen=()
    local src
    for src in NETWORK_INTERFACE_STATE NETWORK_INTERFACE_MTU NETWORK_INTERFACE_MAC \
               NETWORK_INTERFACE_IPV4_ADDRS NETWORK_INTERFACE_IPV6_ADDRS \
               NETWORK_INTERFACE_IPV4_ROUTES NETWORK_INTERFACE_IPV6_ROUTES; do
      if decl=$(declare -p "$src" 2>/dev/null) && [[ "$decl" == declare\ -A* ]]; then
        # nameref to iterate keys dynamically
        declare -n ref="$src"
        local k
        for k in "${!ref[@]}"; do
          if [[ -n "$k" && -z "${seen[$k]:-}" ]]; then
            seen[$k]=1
            iface_list+=("$k")
          fi
        done
      fi
    done
  fi

  local iface
  for iface in "${iface_list[@]}"; do
    [[ -z "$iface" ]] && continue
    connections+=( "$(build_connection_json "$iface")" )
  done
}

# dump_networks_shell
# -------------------
# Output shell declarations describing the collected networking information so
# that other scripts can `source` them and consume the JSON payloads.
dump_networks_shell() {
  local network_report_time="$NETWORK_REPORT_TIME"
  local network_error="$NETWORK_ERROR"
  local -a default_routes_ipv4=("${NETWORK_DEFAULT_ROUTES_IPV4[@]}")
  local -a default_routes_ipv6=("${NETWORK_DEFAULT_ROUTES_IPV6[@]}")

  generate_connections

  declare -p \
    network_report_time \
    network_error \
    default_routes_ipv4 \
    default_routes_ipv6 \
    connections
}

# usage
# -----
usage() {
  cat <<'USAGE'
Usage: inspectnetworksjson.sh [--report | --dump-shell | --help]

  --report       Print a formatted network report (default when executed).
  --dump-shell   Output shell declarations with JSON-encoded network objects.
  --help         Show this help message.
USAGE
}

# inspectnetworks_main [ARGS]
# ---------------------------
inspectnetworks_main() {
  local mode="report"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --report) mode="report" ;;
      --dump-shell) mode="dump-shell" ;;
      --help) usage; return 0 ;;
      *) usage >&2; return 1 ;;
    esac
    shift
  done

  collect_network_info

  case "$mode" in
    report) render_network_report ;;
    dump-shell) dump_networks_shell ;;
    *) return 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  inspectnetworks_main "$@"
fi
