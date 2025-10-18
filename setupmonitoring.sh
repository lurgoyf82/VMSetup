#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if [[ $EUID -ne 0 ]]; then
  msg_error "This script must be run as root."
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  msg_error "This script currently supports Debian/Ubuntu systems with apt-get."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

AGENTS=("node_exporter" "telegraf" "snmpd")

declare -A AGENT_TITLES=(
  ["node_exporter"]="Prometheus Node Exporter"
  ["telegraf"]="Telegraf Agent"
  ["snmpd"]="SNMP Daemon"
)

declare -A AGENT_DESCRIPTIONS=(
  ["node_exporter"]="Exports host metrics for Prometheus on TCP port 9100."
  ["telegraf"]="Collects metrics and exposes them via Prometheus client on TCP port 9273."
  ["snmpd"]="Provides SNMPv2c metrics on UDP port 161."
)

declare -A AGENT_PACKAGES=(
  ["node_exporter"]="prometheus-node-exporter"
  ["telegraf"]="telegraf"
  ["snmpd"]="snmpd"
)

declare -A AGENT_SERVICES=(
  ["node_exporter"]="prometheus-node-exporter"
  ["telegraf"]="telegraf"
  ["snmpd"]="snmpd"
)

declare -A AGENT_PORTS=(
  ["node_exporter"]="9100/tcp"
  ["telegraf"]="9273/tcp"
  ["snmpd"]="161/udp"
)

declare -A SUMMARY_ENDPOINTS

detect_firewall() {
  for svc in ufw firewalld nftables iptables; do
    if systemctl is-active --quiet "$svc"; then
      echo "$svc"
      return
    fi
  done
}

FIREWALL=$(detect_firewall)

open_firewall_port() {
  local port_proto="$1"
  local port="${port_proto%/*}"
  local proto="${port_proto#*/}"

  case "$FIREWALL" in
    ufw)
      ufw allow "$port/$proto" >/dev/null 2>&1 || true
      ;;
    firewalld)
      firewall-cmd --add-port="$port/$proto" --permanent >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      ;;
    nftables)
      nft list table inet filter >/dev/null 2>&1 || nft add table inet filter >/dev/null 2>&1
      nft list chain inet filter input >/dev/null 2>&1 || \
        nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }' >/dev/null 2>&1
      nft add rule inet filter input $proto dport $port counter accept >/dev/null 2>&1 || true
      ;;
    iptables)
      iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1
      ;;
    "")
      ;; # No firewall detected
  esac
}

prompt_listen() {
  local agent="$1"
  local default_ip="0.0.0.0"
  local default_port="${AGENT_PORTS[$agent]%/*}"
  local proto="${AGENT_PORTS[$agent]#*/}"

  local listen_ip listen_port
  if ! listen_ip=$(ask_input "${AGENT_TITLES[$agent]}" "Enter listen IP" "$default_ip"); then
    listen_ip="$default_ip"
  fi

  if [[ "$proto" == "tcp" ]]; then
    if ! listen_port=$(ask_input "${AGENT_TITLES[$agent]}" "Enter listen port" "$default_port"); then
      listen_port="$default_port"
    fi
    echo "$listen_ip:$listen_port"
  else
    echo "$listen_ip:$default_port"
  fi
}

configure_node_exporter() {
  local listen="$1"
  local config="/etc/default/prometheus-node-exporter"

  install -d "$(dirname "$config")"
  cat >"$config" <<EOF_CONF
ARGS="--web.listen-address=${listen} --collector.textfile.directory=/var/lib/prometheus/node-exporter"
EOF_CONF
}

configure_telegraf() {
  local listen="$1"
  local conf_dir="/etc/telegraf/telegraf.d"
  local conf_file="$conf_dir/prometheus-client.conf"

  install -d "$conf_dir"
  cat >"$conf_file" <<EOF_CONF
# Managed by setupmonitoring.sh
[[outputs.prometheus_client]]
  listen = "${listen}"
  metric_version = 2
EOF_CONF
}

configure_snmpd() {
  local listen="$1"
  local addr_ip="${listen%:*}"
  local config="/etc/snmp/snmpd.conf"

  cp "$config" "${config}.bak.$(date +%s)" 2>/dev/null || true
  cat >"$config" <<'EOF_CONF'
# Managed by setupmonitoring.sh
rocommunity public default    -V systemonly
rocommunity6 public default   -V systemonly
sysLocation    "Server Room"
sysContact     "admin@example.com"
EOF_CONF
  echo "agentAddress udp:${addr_ip}:161" >>"$config"
}

install_agent() {
  local agent="$1"
  local listen="$2"
  local package="${AGENT_PACKAGES[$agent]}"
  local service="${AGENT_SERVICES[$agent]}"

  msg_info "Installing ${AGENT_TITLES[$agent]}"
  apt-get install -y "$package"

  case "$agent" in
    node_exporter)
      configure_node_exporter "$listen"
      ;;
    telegraf)
      configure_telegraf "$listen"
      ;;
    snmpd)
      configure_snmpd "$listen"
      ;;
  esac

  systemctl enable "$service" >/dev/null 2>&1
  systemctl restart "$service"

  if systemctl is-active --quiet "$service"; then
    msg_ok "${AGENT_TITLES[$agent]} is active"
  else
    msg_error "${AGENT_TITLES[$agent]} failed to start"
  fi

  if [[ "${AGENT_PORTS[$agent]#*/}" == "tcp" ]]; then
    SUMMARY_ENDPOINTS[$agent]="http://${listen}"
  else
    SUMMARY_ENDPOINTS[$agent]="udp://${listen}"
  fi

  open_firewall_port "${AGENT_PORTS[$agent]}"
}

show_summary() {
  local summary_file
  summary_file=$(mktemp)
  {
    echo "Monitoring setup summary"
    echo
    for agent in "${SELECTED_AGENTS[@]}"; do
      local service="${AGENT_SERVICES[$agent]}"
      local endpoint="${SUMMARY_ENDPOINTS[$agent]}"
      local status="inactive"
      if systemctl is-active --quiet "$service"; then
        status="active"
      fi
      printf "- %s: service %s, endpoint %s\n" "${AGENT_TITLES[$agent]}" "$status" "$endpoint"
    done
    echo
    if [[ -z "$FIREWALL" ]]; then
      echo "No firewall detected; ports are open by default."
    else
      echo "Firewall '${FIREWALL}' updated with required rules."
    fi
  } >"$summary_file"
  show_textbox "Monitoring Summary" "$summary_file" 18 70 1 || true
  rm -f "$summary_file"
}

menu_entries=()
for agent in "${AGENTS[@]}"; do
  menu_entries+=("$agent" "${AGENT_TITLES[$agent]} - ${AGENT_DESCRIPTIONS[$agent]} (default ${AGENT_PORTS[$agent]})" OFF)
done

selection=$(ask_checklist "Monitoring Agents" "Select monitoring agents to install" --size 20 70 8 "${menu_entries[@]}") || selection=""

if [[ -z "$selection" ]]; then
  show_message "Monitoring Agents" "No agents selected. Exiting."
  exit 0
fi

read -r -a SELECTED_AGENTS <<<"$selection"

if [[ ${#SELECTED_AGENTS[@]} -eq 0 ]]; then
  show_message "Monitoring Agents" "No valid agents selected. Exiting."
  exit 0
fi

declare -A LISTEN_ADDRESSES

for agent in "${SELECTED_AGENTS[@]}"; do
  LISTEN_ADDRESSES[$agent]=$(prompt_listen "$agent")

done

msg_info "Updating package index"
apt-get update -y >/dev/null

for agent in "${SELECTED_AGENTS[@]}"; do
  install_agent "$agent" "${LISTEN_ADDRESSES[$agent]}"

done

show_summary
