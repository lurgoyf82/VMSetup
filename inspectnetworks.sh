#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1090
source "${SCRIPT_DIR}/inspectnetwork.sh"

declare -ga CONNECTIONS=()
declare -ga connections=()
declare -gA __CONNECTION_IFACE_MAP=()

sanitize_identifier() {
  local raw="$1"
  local sanitized
  sanitized="${raw//[^a-zA-Z0-9_]/_}"
  if [[ -z "$sanitized" ]]; then
    sanitized="_"
  fi
  [[ $sanitized =~ ^[0-9] ]] && sanitized="_${sanitized}"
  echo "$sanitized"
}

reserve_identifier() {
  local desired="$1"
  local candidate="$desired"
  local index=1
  while [[ -n "${__CONNECTION_IFACE_MAP[$candidate]:-}" ]]; do
    candidate="${desired}_${index}"
    ((index++))
  done
  echo "$candidate"
}

populate_connection_data() {
  CONNECTIONS=()
  connections=()
  __CONNECTION_IFACE_MAP=()

  if [[ -n "${NETWORK_ERROR:-}" ]]; then
    return 0
  fi

  if [[ ${#NETWORK_INTERFACES[@]} -eq 0 ]]; then
    return 0
  fi

  local iface sanitized identifier varname
  for iface in "${NETWORK_INTERFACES[@]}"; do
    [[ -z "$iface" ]] && continue
    sanitized=$(sanitize_identifier "$iface")
    identifier=$(reserve_identifier "$sanitized")
    CONNECTIONS+=("$identifier")
    __CONNECTION_IFACE_MAP["$identifier"]="$iface"
    varname="CONNECTION_${identifier}"
    declare -gA "$varname=()"
    local -n conn_ref="$varname"
    conn_ref[name]="$iface"
    conn_ref[state]="${NETWORK_INTERFACE_STATE[$iface]:-}"
    conn_ref[mac]="${NETWORK_INTERFACE_MAC[$iface]:-}"
    conn_ref[mtu]="${NETWORK_INTERFACE_MTU[$iface]:-}"
    conn_ref[ipv4_addrs]="${NETWORK_INTERFACE_IPV4_ADDRS[$iface]:-}"
    conn_ref[ipv6_addrs]="${NETWORK_INTERFACE_IPV6_ADDRS[$iface]:-}"
    conn_ref[routes_v4]="${NETWORK_INTERFACE_IPV4_ROUTES[$iface]:-}"
    conn_ref[routes_v6]="${NETWORK_INTERFACE_IPV6_ROUTES[$iface]:-}"
  done

  connections=("${CONNECTIONS[@]}")
}

dump_connections_shell() {
  declare -p CONNECTIONS
  declare -p connections
  local identifier varname
  for identifier in "${CONNECTIONS[@]}"; do
    varname="CONNECTION_${identifier}"
    if declare -p "$varname" >/dev/null 2>&1; then
      declare -p "$varname"
    fi
  done
}

usage() {
  cat <<'USAGE'
Usage: inspectnetworks.sh [--report | --dump-shell | --help]

  --report       Print a formatted network report (default when executed).
  --dump-shell   Output shell declarations describing the network state.
  --help         Show this help message.
USAGE
}

inspectnetworks_main() {
  local mode="report"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --report)
        mode="report"
        ;;
      --dump-shell)
        mode="dump-shell"
        ;;
      --help)
        usage
        return 0
        ;;
      *)
        usage >&2
        return 1
        ;;
    esac
    shift
  done

  collect_network_info
  populate_connection_data

  case "$mode" in
    report)
      render_network_report
      ;;
    dump-shell)
      dump_connections_shell
      ;;
    *)
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  inspectnetworks_main "$@"
fi
