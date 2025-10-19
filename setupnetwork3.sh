#!/bin/bash
# Secondary network setup utility focusing on reporting live network details.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/raffolib.sh"

TITLE="Network Inspection"
MESSAGE="Do you want to inspect your current network configuration?"

if ask_yesno "$TITLE" "$MESSAGE"; then
  INFO_FILE=""
  DATA_FILE=""

  cleanup_files() {
    [[ -n "$INFO_FILE" && -f "$INFO_FILE" ]] && rm -f "$INFO_FILE"
    [[ -n "$DATA_FILE" && -f "$DATA_FILE" ]] && rm -f "$DATA_FILE"
  }
  trap cleanup_files EXIT

  INFO_FILE="$(mktemp)"
  DATA_FILE="$(mktemp)"

  if ! "$SCRIPT_DIR/inspectnetwork.sh" --dump-shell >"$DATA_FILE" 2>"$INFO_FILE"; then
    if command -v whiptail >/dev/null 2>&1; then
      whiptail --backtitle "Raffo Setup" \
               --title "Network inspection failed" \
               --textbox "$INFO_FILE" 15 80 || true
    else
      cat "$INFO_FILE"
    fi
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$DATA_FILE"

  MESSAGE_BODY=$'Raffo Setup — Network report\n'
  if [[ -n "${NETWORK_REPORT_TIME:-}" ]]; then
    MESSAGE_BODY+=$'Generated on '
    MESSAGE_BODY+="${NETWORK_REPORT_TIME}"
    MESSAGE_BODY+=$'\n\n'
  else
    MESSAGE_BODY+=$'Generated on (unknown)\n\n'
  fi

  if [[ -n "${NETWORK_ERROR:-}" ]]; then
    MESSAGE_BODY+="${NETWORK_ERROR}"
    [[ "${NETWORK_ERROR}" == *$'\n' ]] || MESSAGE_BODY+=$'\n'
  else
    MESSAGE_BODY+=$'Default routes:\n'

    if [[ ${#NETWORK_DEFAULT_ROUTES_IPV4[@]} -gt 0 ]]; then
      MESSAGE_BODY+=$'  IPv4:\n'
      for LINE in "${NETWORK_DEFAULT_ROUTES_IPV4[@]}"; do
        MESSAGE_BODY+=$'    '
        MESSAGE_BODY+="${LINE}"
        MESSAGE_BODY+=$'\n'
      done
    else
      MESSAGE_BODY+=$'  IPv4: (none detected)\n'
    fi

    if [[ ${#NETWORK_DEFAULT_ROUTES_IPV6[@]} -gt 0 ]]; then
      MESSAGE_BODY+=$'  IPv6:\n'
      for LINE in "${NETWORK_DEFAULT_ROUTES_IPV6[@]}"; do
        MESSAGE_BODY+=$'    '
        MESSAGE_BODY+="${LINE}"
        MESSAGE_BODY+=$'\n'
      done
    else
      MESSAGE_BODY+=$'  IPv6: (none detected)\n'
    fi

    MESSAGE_BODY+=$'\n'

    if [[ ${#NETWORK_INTERFACES[@]} -eq 0 ]]; then
      MESSAGE_BODY+=$'No network interfaces detected.\n'
    else
      for IFACE in "${NETWORK_INTERFACES[@]}"; do
        [[ -z "$IFACE" ]] && continue
        MESSAGE_BODY+=$'Interface: '
        MESSAGE_BODY+="${IFACE}"
        MESSAGE_BODY+=$'\n'

        if [[ -n "${NETWORK_INTERFACE_STATE[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  State: '
          MESSAGE_BODY+="${NETWORK_INTERFACE_STATE[$IFACE]}"
          MESSAGE_BODY+=$'\n'
        fi
        if [[ -n "${NETWORK_INTERFACE_MTU[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  MTU: '
          MESSAGE_BODY+="${NETWORK_INTERFACE_MTU[$IFACE]}"
          MESSAGE_BODY+=$'\n'
        fi
        if [[ -n "${NETWORK_INTERFACE_MAC[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  MAC: '
          MESSAGE_BODY+="${NETWORK_INTERFACE_MAC[$IFACE]}"
          MESSAGE_BODY+=$'\n'
        fi

        if [[ -n "${NETWORK_INTERFACE_IPV4_ADDRS[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  IPv4 addresses:\n'
          while IFS= read -r LINE; do
            MESSAGE_BODY+=$'    '
            MESSAGE_BODY+="${LINE}"
            MESSAGE_BODY+=$'\n'
          done <<<"${NETWORK_INTERFACE_IPV4_ADDRS[$IFACE]}"
        else
          MESSAGE_BODY+=$'  IPv4 addresses: (none)\n'
        fi

        if [[ -n "${NETWORK_INTERFACE_IPV6_ADDRS[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  IPv6 addresses:\n'
          while IFS= read -r LINE; do
            MESSAGE_BODY+=$'    '
            MESSAGE_BODY+="${LINE}"
            MESSAGE_BODY+=$'\n'
          done <<<"${NETWORK_INTERFACE_IPV6_ADDRS[$IFACE]}"
        else
          MESSAGE_BODY+=$'  IPv6 addresses: (none)\n'
        fi

        if [[ -n "${NETWORK_INTERFACE_IPV4_ROUTES[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  IPv4 routes:\n'
          while IFS= read -r LINE; do
            MESSAGE_BODY+=$'    '
            MESSAGE_BODY+="${LINE}"
            MESSAGE_BODY+=$'\n'
          done <<<"${NETWORK_INTERFACE_IPV4_ROUTES[$IFACE]}"
        fi

        if [[ -n "${NETWORK_INTERFACE_IPV6_ROUTES[$IFACE]:-}" ]]; then
          MESSAGE_BODY+=$'  IPv6 routes:\n'
          while IFS= read -r LINE; do
            MESSAGE_BODY+=$'    '
            MESSAGE_BODY+="${LINE}"
            MESSAGE_BODY+=$'\n'
          done <<<"${NETWORK_INTERFACE_IPV6_ROUTES[$IFACE]}"
        fi

        MESSAGE_BODY+=$'\n'
      done
    fi
  fi

  [[ "$MESSAGE_BODY" == *$'\n' ]] || MESSAGE_BODY+=$'\n'
  printf '%s' "$MESSAGE_BODY" >"$INFO_FILE"

  if command -v whiptail >/dev/null 2>&1; then
    whiptail --backtitle "Raffo Setup" \
             --title "Network information" \
             --textbox "$INFO_FILE" 25 90 || true
  else
    printf '%s' "$MESSAGE_BODY"
  fi
else
  if command -v whiptail >/dev/null 2>&1; then
    show_message "$TITLE" "Network inspection skipped."
  else
    echo "Network inspection skipped."
  fi
fi
