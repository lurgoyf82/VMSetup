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
  cleanup_info_file() {
    [[ -n "$INFO_FILE" && -f "$INFO_FILE" ]] && rm -f "$INFO_FILE"
  }
  trap cleanup_info_file EXIT
  INFO_FILE="$(mktemp)"

  {
    echo "Raffo Setup — Network report"
    echo "Generated on $(date -Is)"
    echo

    if ! command -v ip >/dev/null 2>&1; then
      echo "The 'ip' command from iproute2 is required to inspect the network but was not found."
      echo "Please install iproute2 and rerun this module."
    else
      IPV4_DEFAULT=$(ip -4 route show default || true)
      IPV6_DEFAULT=$(ip -6 route show default || true)

      echo "Default routes:"
      if [[ -n "${IPV4_DEFAULT//[[:space:]]/}" ]]; then
        echo "  IPv4:"
        echo "$IPV4_DEFAULT" | sed 's/^/    /'
      else
        echo "  IPv4: (none detected)"
      fi
      if [[ -n "${IPV6_DEFAULT//[[:space:]]/}" ]]; then
        echo "  IPv6:"
        echo "$IPV6_DEFAULT" | sed 's/^/    /'
      else
        echo "  IPv6: (none detected)"
      fi
      echo

      mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}')
      if [[ ${#INTERFACES[@]} -eq 0 ]]; then
        echo "No network interfaces detected."
      else
        for IFACE in "${INTERFACES[@]}"; do
          [[ -z "$IFACE" ]] && continue
          echo "Interface: $IFACE"

          LINK_LINE=$(ip -o link show dev "$IFACE" 2>/dev/null || true)
          if [[ -n "$LINK_LINE" ]]; then
            STATE=$(awk '{for (i=1; i<=NF; i++) if ($i == "state") {print $(i+1); exit}}' <<<"$LINK_LINE")
            MAC=$(awk '{for (i=1; i<=NF; i++) if ($i == "link/ether") {print $(i+1); exit}}' <<<"$LINK_LINE")
            MTU=$(awk '{for (i=1; i<=NF; i++) if ($i == "mtu") {print $(i+1); exit}}' <<<"$LINK_LINE")
            [[ -n "$STATE" ]] && echo "  State: $STATE"
            [[ -n "$MTU" ]] && echo "  MTU: $MTU"
            [[ -n "$MAC" ]] && echo "  MAC: $MAC"
          else
            echo "  Unable to read link information."
          fi

          IPV4_ADDRS=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null || true)
          if [[ -n "$IPV4_ADDRS" ]]; then
            echo "  IPv4 addresses:"
            while IFS= read -r LINE; do
              [[ -z "$LINE" ]] && continue
              ADDR=$(awk '{print $4}' <<<"$LINE")
              META=$(awk '{for (i=1; i<=4; ++i) $i=""; sub(/^ +/, ""); print}' <<<"$LINE")
              if [[ -n "$META" ]]; then
                echo "    $ADDR ($META)"
              else
                echo "    $ADDR"
              fi
            done <<<"$IPV4_ADDRS"
          else
            echo "  IPv4 addresses: (none)"
          fi

          IPV6_ADDRS=$(ip -o -6 addr show dev "$IFACE" 2>/dev/null || true)
          if [[ -n "$IPV6_ADDRS" ]]; then
            echo "  IPv6 addresses:"
            while IFS= read -r LINE; do
              [[ -z "$LINE" ]] && continue
              ADDR=$(awk '{print $4}' <<<"$LINE")
              META=$(awk '{for (i=1; i<=4; ++i) $i=""; sub(/^ +/, ""); print}' <<<"$LINE")
              if [[ -n "$META" ]]; then
                echo "    $ADDR ($META)"
              else
                echo "    $ADDR"
              fi
            done <<<"$IPV6_ADDRS"
          else
            echo "  IPv6 addresses: (none)"
          fi

          DEV_ROUTES=$(ip -4 route show dev "$IFACE" 2>/dev/null | sed 's/^/    /' || true)
          if [[ -n "${DEV_ROUTES//[[:space:]]/}" ]]; then
            echo "  IPv4 routes:"
            echo "$DEV_ROUTES"
          fi

          DEV6_ROUTES=$(ip -6 route show dev "$IFACE" 2>/dev/null | sed 's/^/    /' || true)
          if [[ -n "${DEV6_ROUTES//[[:space:]]/}" ]]; then
            echo "  IPv6 routes:"
            echo "$DEV6_ROUTES"
          fi

          echo
        done
      fi
    fi
  } >"$INFO_FILE"

  if command -v whiptail >/dev/null 2>&1; then
    whiptail --backtitle "Raffo Setup" \
             --title "Network information" \
             --textbox "$INFO_FILE" 25 90
  else
    cat "$INFO_FILE"
  fi
else
  if command -v whiptail >/dev/null 2>&1; then
    show_message "$TITLE" "Network inspection skipped."
  else
    echo "Network inspection skipped."
  fi
fi
