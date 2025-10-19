#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

LOG_DIR="/var/log/raffosetup"
CLEANUP_LOG="$LOG_DIR/cleanup.log"
SUMMARY_FILE="$LOG_DIR/summary.txt"
STAMP_FILE="/var/lib/raffosetup/.done"

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$STAMP_FILE")"
touch "$CLEANUP_LOG"

log_timestamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

run_logged() {
  local description="$1"
  shift
  msg_info "$description"
  {
    echo "[$(log_timestamp)] $description"
    "$@"
  } >>"$CLEANUP_LOG" 2>&1 && {
    msg_ok "$description"
  } || {
    msg_error "$description failed (see $CLEANUP_LOG)"
    return 1
  }
}

export DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-noninteractive}

run_logged "Running apt autoremove" apt-get -y autoremove --purge
run_logged "Running apt clean" apt-get clean
run_logged "Removing leftover temporary files" bash -c '
  set -euo pipefail
  for dir in /tmp /var/tmp; do
    if [[ -d "$dir" ]]; then
      find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    fi
  done
'

if command -v logrotate >/dev/null 2>&1; then
  run_logged "Rotating logs" logrotate -f /etc/logrotate.conf
else
  msg_info "Rotating logs"
  echo "[$(log_timestamp)] logrotate not installed; skipping" >>"$CLEANUP_LOG"
  msg_ok "Rotating logs (skipped - logrotate not installed)"
fi

collect_ips() {
  local family="$1" label="$2"
  local output
  if output=$(ip -o "$family" addr show scope global 2>/dev/null); then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local iface addr
      iface=$(awk '{print $2}' <<<"$line")
      addr=$(awk '{print $4}' <<<"$line")
      IP_LINES+=("${label} ${addr} on ${iface}")
    done <<<"$output"
  fi
}

FIREWALL_NAME="none"
FIREWALL_POLICY="n/a"
for svc in ufw firewalld nftables iptables; do
  if systemctl is-active --quiet "$svc"; then
    FIREWALL_NAME="$svc"
    case "$svc" in
      ufw)
        FIREWALL_POLICY=$(ufw status | awk -F': ' '/Default:/ {print $2; exit}')
        FIREWALL_POLICY=${FIREWALL_POLICY:-unknown}
        ;;
      firewalld)
        FIREWALL_POLICY=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
        ;;
      nftables)
        policy_line=$(nft list chain inet filter input 2>/dev/null | awk '/policy/ {print $NF; exit}')
        FIREWALL_POLICY=${policy_line%%;}
        [[ -z "$FIREWALL_POLICY" ]] && FIREWALL_POLICY="unknown"
        ;;
      iptables)
        chain_header=$(iptables -L INPUT -n 2>/dev/null | head -n1)
        if [[ "$chain_header" =~ policy[[:space:]]([A-Z]+) ]]; then
          FIREWALL_POLICY="${BASH_REMATCH[1]}"
        else
          FIREWALL_POLICY="unknown"
        fi
        ;;
    esac
    break
  fi
done

HOSTNAME=$(hostnamectl --static 2>/dev/null || hostname)
IP_LINES=()
collect_ips -4 "IPv4"
collect_ips -6 "IPv6"

AGENTS=()
add_agent() {
  local pkg="$1" service="$2" label="$3"
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
    local status="installed"
    if [[ -n "$service" ]]; then
      if systemctl is-active --quiet "$service"; then
        status+=" & active"
      else
        status+=" (service inactive)"
      fi
    fi
    AGENTS+=("$label: $status")
  fi
}
add_agent "qemu-guest-agent" "qemu-guest-agent" "QEMU Guest Agent"
add_agent "open-vm-tools" "open-vm-tools" "VMware Guest Agent"
add_agent "hyperv-daemons" "hv-kvp-daemon.service" "Hyper-V Guest Agent"
add_agent "virtualbox-guest-utils" "" "VirtualBox Guest Utils"

PENDING_REBOOT="No"
if [[ -f /var/run/reboot-required ]]; then
  PENDING_REBOOT="Yes"
fi

{
  echo "Raffo Setup Summary"
  echo "===================="
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S %Z')"
  echo "Hostname: $HOSTNAME"
  echo
  echo "IP Addresses:"
  if ((${#IP_LINES[@]})); then
    for entry in "${IP_LINES[@]}"; do
      echo "  - $entry"
    done
  else
    echo "  (none)"
  fi
  echo
  echo "Firewall:" 
  echo "  Active: $FIREWALL_NAME"
  echo "  Policy: $FIREWALL_POLICY"
  echo
  echo "Guest Agents:"
  if ((${#AGENTS[@]})); then
    for entry in "${AGENTS[@]}"; do
      echo "  - $entry"
    done
  else
    echo "  - None detected"
  fi
  echo
  echo "Pending Reboot: $PENDING_REBOOT"
} >"$SUMMARY_FILE"

msg_ok "Summary written to $SUMMARY_FILE"

touch "$STAMP_FILE"
msg_ok "Marked completion stamp at $STAMP_FILE"

msg_ok "Cleanup tasks finished"
