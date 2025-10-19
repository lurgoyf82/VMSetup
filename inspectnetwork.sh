#!/bin/bash
# Generate a comprehensive network report for Raffo Setup or expose it as
# structured shell variables that other modules can consume.

NETWORK_REPORT_TIME=""
NETWORK_ERROR=""
NETWORK_DEFAULT_ROUTES_IPV4=()
NETWORK_DEFAULT_ROUTES_IPV6=()
NETWORK_INTERFACES=()
declare -A NETWORK_INTERFACE_STATE
declare -A NETWORK_INTERFACE_MTU
declare -A NETWORK_INTERFACE_MAC
declare -A NETWORK_INTERFACE_IPV4_ADDRS
declare -A NETWORK_INTERFACE_IPV6_ADDRS
declare -A NETWORK_INTERFACE_IPV4_ROUTES
declare -A NETWORK_INTERFACE_IPV6_ROUTES

reset_network_data() {
  NETWORK_REPORT_TIME=""
  NETWORK_ERROR=""
  NETWORK_DEFAULT_ROUTES_IPV4=()
  NETWORK_DEFAULT_ROUTES_IPV6=()
  NETWORK_INTERFACES=()
  NETWORK_INTERFACE_STATE=()
  NETWORK_INTERFACE_MTU=()
  NETWORK_INTERFACE_MAC=()
  NETWORK_INTERFACE_IPV4_ADDRS=()
  NETWORK_INTERFACE_IPV6_ADDRS=()
  NETWORK_INTERFACE_IPV4_ROUTES=()
  NETWORK_INTERFACE_IPV6_ROUTES=()
}

collect_network_info() {
  reset_network_data

  NETWORK_REPORT_TIME="$(date -Is)"

  if ! command -v ip >/dev/null 2>&1; then
    NETWORK_ERROR=$'The \'ip\' command from iproute2 is required to inspect the network but was not found.\nPlease install iproute2 and rerun this module.'
    return 0
  fi

  mapfile -t NETWORK_DEFAULT_ROUTES_IPV4 < <(ip -4 route show default 2>/dev/null || true)
  mapfile -t NETWORK_DEFAULT_ROUTES_IPV6 < <(ip -6 route show default 2>/dev/null || true)
  mapfile -t NETWORK_INTERFACES < <(ip -o link show | awk -F': ' '{print $2}')

  if [[ ${#NETWORK_INTERFACES[@]} -eq 0 ]]; then
    NETWORK_ERROR="No network interfaces detected."
    return 0
  fi

  local IFACE LINK_LINE STATE MAC MTU ADDR LINE
  local -a IPV4_LINES IPV6_LINES ROUTE_LINES ROUTE6_LINES
  local formatted

  for IFACE in "${NETWORK_INTERFACES[@]}"; do
    [[ -z "$IFACE" ]] && continue

    LINK_LINE=$(ip -o link show dev "$IFACE" 2>/dev/null || true)
    if [[ -n "$LINK_LINE" ]]; then
      STATE=$(awk '{for (i=1; i<=NF; i++) if ($i == "state") {print $(i+1); exit}}' <<<"$LINK_LINE")
      MAC=$(awk '{for (i=1; i<=NF; i++) if ($i == "link/ether") {print $(i+1); exit}}' <<<"$LINK_LINE")
      MTU=$(awk '{for (i=1; i<=NF; i++) if ($i == "mtu") {print $(i+1); exit}}' <<<"$LINK_LINE")
      [[ -n "$STATE" ]] && NETWORK_INTERFACE_STATE["$IFACE"]="$STATE"
      [[ -n "$MTU" ]] && NETWORK_INTERFACE_MTU["$IFACE"]="$MTU"
      [[ -n "$MAC" ]] && NETWORK_INTERFACE_MAC["$IFACE"]="$MAC"
    fi

    mapfile -t IPV4_LINES < <(ip -o -4 addr show dev "$IFACE" 2>/dev/null || true)
    if [[ ${#IPV4_LINES[@]} -gt 0 ]]; then
      formatted=""
      for LINE in "${IPV4_LINES[@]}"; do
        [[ -z "$LINE" ]] && continue
        ADDR=$(awk '{print $4}' <<<"$LINE")
        if [[ -n "$formatted" ]]; then
          formatted+=$'\n'
        fi
        formatted+="$ADDR"
      done
      NETWORK_INTERFACE_IPV4_ADDRS["$IFACE"]="$formatted"
    else
      NETWORK_INTERFACE_IPV4_ADDRS["$IFACE"]=""
    fi

    mapfile -t IPV6_LINES < <(ip -o -6 addr show dev "$IFACE" 2>/dev/null || true)
    if [[ ${#IPV6_LINES[@]} -gt 0 ]]; then
      formatted=""
      for LINE in "${IPV6_LINES[@]}"; do
        [[ -z "$LINE" ]] && continue
        ADDR=$(awk '{print $4}' <<<"$LINE")
        if [[ -n "$formatted" ]]; then
          formatted+=$'\n'
        fi
        formatted+="$ADDR"
      done
      NETWORK_INTERFACE_IPV6_ADDRS["$IFACE"]="$formatted"
    else
      NETWORK_INTERFACE_IPV6_ADDRS["$IFACE"]=""
    fi

    mapfile -t ROUTE_LINES < <(ip -4 route show dev "$IFACE" 2>/dev/null || true)
    if [[ ${#ROUTE_LINES[@]} -gt 0 ]]; then
      formatted=""
      for LINE in "${ROUTE_LINES[@]}"; do
        [[ -z "$LINE" ]] && continue
        if [[ -n "$formatted" ]]; then
          formatted+=$'\n'
        fi
        formatted+="$LINE"
      done
      NETWORK_INTERFACE_IPV4_ROUTES["$IFACE"]="$formatted"
    else
      NETWORK_INTERFACE_IPV4_ROUTES["$IFACE"]=""
    fi

    mapfile -t ROUTE6_LINES < <(ip -6 route show dev "$IFACE" 2>/dev/null || true)
    if [[ ${#ROUTE6_LINES[@]} -gt 0 ]]; then
      formatted=""
      for LINE in "${ROUTE6_LINES[@]}"; do
        [[ -z "$LINE" ]] && continue
        if [[ -n "$formatted" ]]; then
          formatted+=$'\n'
        fi
        formatted+="$LINE"
      done
      NETWORK_INTERFACE_IPV6_ROUTES["$IFACE"]="$formatted"
    else
      NETWORK_INTERFACE_IPV6_ROUTES["$IFACE"]=""
    fi
  done

  return 0
}

render_network_report() {
  printf 'Raffo Setup — Network report\n'
  printf 'Generated on %s\n\n' "$NETWORK_REPORT_TIME"

  if [[ -n "$NETWORK_ERROR" ]]; then
    printf '%b\n' "$NETWORK_ERROR"
    return 0
  fi

  echo "Default routes:"
  if [[ ${#NETWORK_DEFAULT_ROUTES_IPV4[@]} -gt 0 ]]; then
    echo "  IPv4:"
    printf '    %s\n' "${NETWORK_DEFAULT_ROUTES_IPV4[@]}"
  else
    echo "  IPv4: (none detected)"
  fi

  if [[ ${#NETWORK_DEFAULT_ROUTES_IPV6[@]} -gt 0 ]]; then
    echo "  IPv6:"
    printf '    %s\n' "${NETWORK_DEFAULT_ROUTES_IPV6[@]}"
  else
    echo "  IPv6: (none detected)"
  fi
  echo

  local IFACE LINE
  for IFACE in "${NETWORK_INTERFACES[@]}"; do
    [[ -z "$IFACE" ]] && continue
    echo "Interface: $IFACE"

    [[ -n "${NETWORK_INTERFACE_STATE[$IFACE]:-}" ]] && echo "  State: ${NETWORK_INTERFACE_STATE[$IFACE]}"
    [[ -n "${NETWORK_INTERFACE_MTU[$IFACE]:-}" ]] && echo "  MTU: ${NETWORK_INTERFACE_MTU[$IFACE]}"
    [[ -n "${NETWORK_INTERFACE_MAC[$IFACE]:-}" ]] && echo "  MAC: ${NETWORK_INTERFACE_MAC[$IFACE]}"

    if [[ -n "${NETWORK_INTERFACE_IPV4_ADDRS[$IFACE]:-}" ]]; then
      echo "  IPv4 addresses:"
      while IFS= read -r LINE; do
        printf '    %s\n' "$LINE"
      done <<<"${NETWORK_INTERFACE_IPV4_ADDRS[$IFACE]}"
    else
      echo "  IPv4 addresses: (none)"
    fi

    if [[ -n "${NETWORK_INTERFACE_IPV6_ADDRS[$IFACE]:-}" ]]; then
      echo "  IPv6 addresses:"
      while IFS= read -r LINE; do
        printf '    %s\n' "$LINE"
      done <<<"${NETWORK_INTERFACE_IPV6_ADDRS[$IFACE]}"
    else
      echo "  IPv6 addresses: (none)"
    fi

    if [[ -n "${NETWORK_INTERFACE_IPV4_ROUTES[$IFACE]:-}" ]]; then
      echo "  IPv4 routes:"
      while IFS= read -r LINE; do
        printf '    %s\n' "$LINE"
      done <<<"${NETWORK_INTERFACE_IPV4_ROUTES[$IFACE]}"
    fi

    if [[ -n "${NETWORK_INTERFACE_IPV6_ROUTES[$IFACE]:-}" ]]; then
      echo "  IPv6 routes:"
      while IFS= read -r LINE; do
        printf '    %s\n' "$LINE"
      done <<<"${NETWORK_INTERFACE_IPV6_ROUTES[$IFACE]}"
    fi

    echo
  done

  return 0
}

dump_network_shell() {
  declare -p \
    NETWORK_REPORT_TIME \
    NETWORK_ERROR \
    NETWORK_DEFAULT_ROUTES_IPV4 \
    NETWORK_DEFAULT_ROUTES_IPV6 \
    NETWORK_INTERFACES \
    NETWORK_INTERFACE_STATE \
    NETWORK_INTERFACE_MTU \
    NETWORK_INTERFACE_MAC \
    NETWORK_INTERFACE_IPV4_ADDRS \
    NETWORK_INTERFACE_IPV6_ADDRS \
    NETWORK_INTERFACE_IPV4_ROUTES \
    NETWORK_INTERFACE_IPV6_ROUTES
}

usage() {
  cat <<'EOF'
Usage: inspectnetwork.sh [--report | --dump-shell | --help]

  --report       Print a formatted network report (default when executed).
  --dump-shell   Output shell declarations describing the network state.
  --help         Show this help message.
EOF
}

inspectnetwork_main() {
  set -euo pipefail

  local MODE="report"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --report)
        MODE="report"
        ;;
      --dump-shell)
        MODE="dump-shell"
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

  case "$MODE" in
    report)
      render_network_report
      ;;
    dump-shell)
      dump_network_shell
      ;;
    *)
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  inspectnetwork_main "$@"
fi
