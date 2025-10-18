#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if [[ $EUID -ne 0 ]]; then
  msg_error "This script must be run as root."
  exit 1
fi

LOG_FILE="/var/log/setupservices.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

show_message "Service Checklist" "Review current service state before making changes."

SERVICES=(
  "fstrim.timer"
  "chrony.service|chronyd.service"
  "getty@ttyS0.service"
  "irqbalance.service"
)

declare -A SERVICE_DESCRIPTIONS=(
  ["fstrim.timer"]="SSD/TRIM optimization timer"
  ["chrony.service"]="Chrony time synchronization service"
  ["chronyd.service"]="Chrony time synchronization service"
  ["getty@ttyS0.service"]="Serial console login"
  ["irqbalance.service"]="IRQ load balancing"
)

resolve_unit() {
  local entry="$1"
  local candidate
  IFS='|' read -ra CANDIDATES <<< "$entry"
  for candidate in "${CANDIDATES[@]}"; do
    if systemctl list-unit-files "$candidate" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

describe_unit() {
  local entry="$1"
  IFS='|' read -ra CANDIDATES <<< "$entry"
  for candidate in "${CANDIDATES[@]}"; do
    if [[ -n "${SERVICE_DESCRIPTIONS[$candidate]:-}" ]]; then
      echo "${SERVICE_DESCRIPTIONS[$candidate]}"
      return 0
    fi
  done
  echo ""
}

print_status_table() {
  local tmp
  tmp=$(mktemp)
  {
    printf "%-25s %-10s %-10s %-40s\n" "Unit" "Enabled" "Active" "Description"
    printf '%0.s-' {1..90}
    printf "\n"
    local entry unit enabled active desc
    for entry in "${SERVICES[@]}"; do
      if ! unit=$(resolve_unit "$entry"); then
        printf "%-25s %-10s %-10s %-40s\n" "$entry" "n/a" "n/a" "(unit not present)"
        continue
      fi
      enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "disabled")
      active=$(systemctl is-active "$unit" 2>/dev/null || echo "inactive")
      desc=$(describe_unit "$entry")
      printf "%-25s %-10s %-10s %-40s\n" "$unit" "$enabled" "$active" "$desc"
    done
  } >"$tmp"
  show_textbox "Service Status" "$tmp" 20 80 1 || true
  rm -f "$tmp"
}

prompt_action() {
  local unit="$1"
  local enabled="$2"
  local choice
  choice=$(ask_menu "Service Action" "Current state for $unit: $enabled" \
    "enable" "Enable and start" \
    "disable" "Disable and stop" \
    "skip" "Leave unchanged") || choice="skip"
  echo "$choice"
}

apply_service_action() {
  local unit="$1"
  local action="$2"
  local message status
  case "$action" in
    enable)
      if systemctl enable --now "$unit" >/tmp/setupservices.tmp 2>&1; then
        message="Enabled $unit"
        status="ok"
      else
        message="Failed to enable $unit: $(cat /tmp/setupservices.tmp)"
        status="error"
      fi
      ;;
    disable)
      if systemctl disable --now "$unit" >/tmp/setupservices.tmp 2>&1; then
        message="Disabled $unit"
        status="ok"
      else
        message="Failed to disable $unit: $(cat /tmp/setupservices.tmp)"
        status="error"
      fi
      ;;
    *)
      message="Skipped $unit"
      status="info"
      ;;
  esac
  rm -f /tmp/setupservices.tmp
  case "$status" in
    ok) msg_ok "$message" ;;
    error) msg_error "$message" ;;
    info) msg_info "$message" ;;
  esac
  echo "$(date --iso-8601=seconds) - $message" >>"$LOG_FILE"
}

optional_roles_menu() {
  while true; do
    local choice
    choice=$(ask_menu "Optional Roles" "Select an action" \
      "docker" "Install Docker" \
      "podman" "Install Podman" \
      "return" "Return to main menu") || choice="return"
    case "$choice" in
      docker)
        install_docker
        ;;
      podman)
        install_podman
        ;;
      return)
        return 0
        ;;
    esac
  done
}

detect_pkg_manager() {
  for pm in apt-get dnf yum zypper pacman; do
    if command -v "$pm" >/dev/null 2>&1; then
      echo "$pm"
      return 0
    fi
  done
  return 1
}

install_docker() {
  local pm
  if command -v docker >/dev/null 2>&1; then
    msg_info "Docker already installed."
    return 0
  fi
  if ! pm=$(detect_pkg_manager); then
    msg_error "Could not detect supported package manager for Docker installation."
    return 1
  fi
  msg_info "Installing Docker with $pm"
  case "$pm" in
    apt-get)
      apt-get update
      apt-get install -y docker.io
      ;;
    dnf|yum)
      "$pm" install -y docker
      ;;
    zypper)
      zypper install -y docker
      ;;
    pacman)
      pacman -Sy --noconfirm docker
      ;;
  esac
  systemctl enable --now docker >/dev/null 2>&1 || true
  msg_ok "Docker installation complete."
  echo "$(date --iso-8601=seconds) - Docker installation attempted with $pm" >>"$LOG_FILE"
}

install_podman() {
  local pm
  if command -v podman >/dev/null 2>&1; then
    msg_info "Podman already installed."
    return 0
  fi
  if ! pm=$(detect_pkg_manager); then
    msg_error "Could not detect supported package manager for Podman installation."
    return 1
  fi
  msg_info "Installing Podman with $pm"
  case "$pm" in
    apt-get)
      apt-get update
      apt-get install -y podman
      ;;
    dnf|yum)
      "$pm" install -y podman
      ;;
    zypper)
      zypper install -y podman
      ;;
    pacman)
      pacman -Sy --noconfirm podman
      ;;
  esac
  msg_ok "Podman installation complete."
  echo "$(date --iso-8601=seconds) - Podman installation attempted with $pm" >>"$LOG_FILE"
}

print_status_table

declare -a ACTIONS=()
declare -a UNITS=()

for entry in "${SERVICES[@]}"; do
  if ! unit=$(resolve_unit "$entry"); then
    msg_info "Skipping $entry (unit not present)"
    continue
  fi
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "disabled")
  action=$(prompt_action "$unit" "$enabled")
  ACTIONS+=("$action")
  UNITS+=("$unit")

done

for idx in "${!UNITS[@]}"; do
  apply_service_action "${UNITS[$idx]}" "${ACTIONS[$idx]}"

done

if printf '%s\n' "${ACTIONS[@]}" | grep -qE '^(enable|disable)$'; then
  msg_info "Reloading systemd daemon to ensure changes are registered"
  systemctl daemon-reload
  msg_ok "systemd daemon reloaded"
  echo "$(date --iso-8601=seconds) - systemd daemon reloaded" >>"$LOG_FILE"
fi

if ask_yesno "Optional Roles" "Open optional role installer menu?"; then
  optional_roles_menu
fi

print_status_table

show_message "Services" "Configuration complete. Summary logged to $LOG_FILE."
