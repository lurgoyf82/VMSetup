#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

LOG_FILE="/var/log/setupservices.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

echo "=== Service configuration checklist ==="

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
  echo
}

prompt_action() {
  local unit="$1"
  local enabled="$2"
  local action
  while true; do
    read -rp "Action for $unit (current: $enabled) [e]nable/[d]isable/[s]kip: " action
    case "${action,,}" in
      e|enable) echo "enable"; return 0 ;;
      d|disable) echo "disable"; return 0 ;;
      s|skip|"" ) echo "skip"; return 0 ;;
    esac
    echo "Invalid choice."
  done
}

apply_service_action() {
  local unit="$1"
  local action="$2"
  local message
  case "$action" in
    enable)
      if systemctl enable --now "$unit" >/tmp/setupservices.tmp 2>&1; then
        message="Enabled $unit"
      else
        message="Failed to enable $unit: $(cat /tmp/setupservices.tmp)"
      fi
      ;;
    disable)
      if systemctl disable --now "$unit" >/tmp/setupservices.tmp 2>&1; then
        message="Disabled $unit"
      else
        message="Failed to disable $unit: $(cat /tmp/setupservices.tmp)"
      fi
      ;;
    *)
      message="Skipped $unit"
      ;;
  esac
  rm -f /tmp/setupservices.tmp
  echo "$message"
  echo "$(date --iso-8601=seconds) - $message" >>"$LOG_FILE"
}

optional_roles_menu() {
  while true; do
    echo
    echo "Optional role installers"
    echo "1) Install Docker"
    echo "2) Install Podman"
    echo "3) Return to main menu"
    read -rp "Select an option: " choice
    case "$choice" in
      1)
        install_docker
        ;;
      2)
        install_podman
        ;;
      3)
        return 0
        ;;
      *)
        echo "Invalid selection."
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
    echo "Docker already installed."
    return 0
  fi
  if ! pm=$(detect_pkg_manager); then
    echo "Could not detect supported package manager for Docker installation."
    return 1
  fi
  echo "Installing Docker with $pm..."
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
  echo "Docker installation complete."
  echo "$(date --iso-8601=seconds) - Docker installation attempted with $pm" >>"$LOG_FILE"
}

install_podman() {
  local pm
  if command -v podman >/dev/null 2>&1; then
    echo "Podman already installed."
    return 0
  fi
  if ! pm=$(detect_pkg_manager); then
    echo "Could not detect supported package manager for Podman installation."
    return 1
  fi
  echo "Installing Podman with $pm..."
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
  echo "Podman installation complete."
  echo "$(date --iso-8601=seconds) - Podman installation attempted with $pm" >>"$LOG_FILE"
}

print_status_table

declare -a ACTIONS=()
declare -a UNITS=()

for entry in "${SERVICES[@]}"; do
  if ! unit=$(resolve_unit "$entry"); then
    echo "Skipping $entry because no matching unit is installed."
    continue
  fi
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "disabled")
  action=$(prompt_action "$unit" "$enabled")
  ACTIONS+=("$action")
  UNITS+=("$unit")
  echo

done

for idx in "${!UNITS[@]}"; do
  apply_service_action "${UNITS[$idx]}" "${ACTIONS[$idx]}"

done

if printf '%s\n' "${ACTIONS[@]}" | grep -qE '^(enable|disable)$'; then
  echo "Reloading systemd daemon to ensure changes are registered..."
  systemctl daemon-reload
  echo "$(date --iso-8601=seconds) - systemd daemon reloaded" >>"$LOG_FILE"
fi

echo
read -rp "Open optional role installer menu? [y/N]: " role_choice
if [[ "${role_choice,,}" == "y" || "${role_choice,,}" == "yes" ]]; then
  optional_roles_menu
fi

echo
print_status_table

echo "Configuration complete. Summary logged to $LOG_FILE."
