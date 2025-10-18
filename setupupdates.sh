#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

export DEBIAN_FRONTEND=noninteractive

msg_info "Refreshing package lists"
apt-get update -y >/dev/null
msg_ok "Package lists refreshed"

msg_info "Applying full upgrade"
apt-get full-upgrade -y
msg_ok "Full upgrade completed"

msg_info "Ensuring kernel headers are installed"
KERNEL_HEADERS_PACKAGE="linux-headers-$(uname -r)"
if apt-get install -y --no-install-recommends "$KERNEL_HEADERS_PACKAGE"; then
  msg_ok "Kernel headers installed for $(uname -r)"
else
  msg_error "Kernel headers package $KERNEL_HEADERS_PACKAGE is unavailable"
fi

install_microcode() {
  local vendor="$(awk -F': ' '/vendor_id/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "")"
  local packages=()
  local title message

  case "${vendor}" in
    GenuineIntel)
      packages+=(intel-microcode)
      title="Intel Microcode"
      message="Install intel-microcode package to receive CPU microcode updates?"
      ;;
    AuthenticAMD)
      packages+=(amd64-microcode)
      title="AMD Microcode"
      message="Install amd64-microcode package to receive CPU microcode updates?"
      ;;
    *)
      packages=()
      ;;
  esac

  if ((${#packages[@]} == 0)); then
    msg_ok "No supported CPU microcode package detected"
    return
  fi

  if ask_yesno "$title" "$message"; then
    msg_info "Installing CPU microcode packages"
    apt-get install -y "${packages[@]}"
    msg_ok "CPU microcode packages installed"
  else
    msg_ok "CPU microcode installation skipped"
  fi
}

install_microcode

configure_unattended_upgrades() {
  msg_info "Configuring unattended-upgrades"
  apt-get install -y unattended-upgrades >/dev/null

  local auto_conf="/etc/apt/apt.conf.d/20auto-upgrades"
  local override_conf="/etc/apt/apt.conf.d/51raffo-unattended-upgrades"

  raffo_backup "$auto_conf" "20auto-upgrades" >/dev/null || true
  tee "$auto_conf" >/dev/null <<'EOC'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOC

  raffo_backup "$override_conf" "51raffo-unattended-upgrades" >/dev/null || true

  local reboot_enabled="false"
  local reboot_time=""
  if ask_yesno "Automatic Reboots" "Enable automatic reboots when required after unattended upgrades?"; then
    reboot_enabled="true"
    reboot_time="$(ask_input "Reboot Window" "Enter a reboot time window (HH:MM, 24h). Leave empty for immediate reboots." "02:00" || true)"
  fi

  tee "$override_conf" >/dev/null <<'EOC'
Unattended-Upgrade::Origins-Pattern {
        "origin=${distro_id},codename=${distro_codename}-security";
        "origin=${distro_id},label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "${reboot_enabled}";
EOC

  if [[ -n "$reboot_time" ]]; then
    tee -a "$override_conf" >/dev/null <<'EOC'
Unattended-Upgrade::Automatic-Reboot-Time "${reboot_time}";
EOC
  fi

  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
  msg_ok "unattended-upgrades configured"
}

configure_unattended_upgrades

record_reboot_requirement() {
  local marker_file="${RAFFO_STATE_DIR}/reboot-required"
  if [[ -f /var/run/reboot-required ]]; then
    cp /var/run/reboot-required "$marker_file"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
      cp /var/run/reboot-required.pkgs "${marker_file}.pkgs"
    fi
    msg_info "System reboot required"
    msg_ok "Reboot requirement recorded at $marker_file"
  else
    rm -f "$marker_file" "${marker_file}.pkgs"
    msg_ok "No reboot required"
  fi
}

record_reboot_requirement

msg_ok "Update and maintenance tasks completed"
