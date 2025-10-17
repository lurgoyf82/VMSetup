#!/usr/bin/env bash
set -euo pipefail
source /root/raffolib.sh

ensure_serial_console() {
  local grub_file="/etc/default/grub"
  local console_flags="console=tty0 console=ttyS0,115200n8"
  local updated=0

  if [[ ! -f "$grub_file" ]]; then
    msg_error "${grub_file} not found; skipping serial console configuration"
    return
  fi

  local backup
  backup=$(raffo_backup "$grub_file" "grub-default") || true
  if [[ -n "${backup:-}" ]]; then
    msg_ok "Backed up grub defaults to ${backup}"
  fi

  local current_line
  current_line=$(grep '^GRUB_CMDLINE_LINUX=' "$grub_file" || true)
  if [[ -z "$current_line" ]]; then
    msg_info "Adding GRUB_CMDLINE_LINUX with serial console flags"
    printf '\nGRUB_CMDLINE_LINUX="%s"\n' "$console_flags" >>"$grub_file"
    updated=1
  else
    local current_value
    current_value=$(echo "$current_line" | sed -E 's/^GRUB_CMDLINE_LINUX="?(.*)"?$/\1/')
    if [[ "$current_value" != *"console=ttyS0,115200n8"* ]]; then
      msg_info "Appending serial console flags to GRUB_CMDLINE_LINUX"
      [[ -n "$current_value" && "$current_value" != "\"\"" ]] && current_value+=" "
      current_value+="$console_flags"
      current_value=${current_value//\"/\\\"}
      sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${current_value}\"|" "$grub_file"
      updated=1
    else
      msg_ok "Serial console flags already present in GRUB_CMDLINE_LINUX"
    fi
  fi

  if (( updated )); then
    msg_info "Updating grub configuration"
    update-grub >/dev/null 2>&1 || update-grub
    msg_ok "Grub configuration updated"
  fi

  if systemctl list-unit-files serial-getty@ttyS0.service >/dev/null 2>&1; then
    msg_info "Ensuring serial-getty@ttyS0.service is enabled"
    systemctl enable --now serial-getty@ttyS0.service
    msg_ok "serial-getty@ttyS0.service enabled"
  else
    msg_error "serial-getty@ttyS0.service unit not found"
  fi
}

install_package_if_missing() {
  local package="$1"
  if dpkg -s "$package" >/dev/null 2>&1; then
    msg_ok "$package already installed"
  else
    msg_info "Installing ${package}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
    msg_ok "${package} installed"
  fi
}

enable_services() {
  local services=("$@")
  local enabled_any=0
  for svc in "${services[@]}"; do
    [[ -z "$svc" ]] && continue
    if systemctl list-unit-files "$svc" >/dev/null 2>&1; then
      msg_info "Enabling ${svc}"
      systemctl enable --now "$svc"
      msg_ok "${svc} enabled"
      enabled_any=1
    else
      msg_error "${svc} unit not present; skipping"
    fi
  done
  (( enabled_any )) || msg_error "No guest agent services were enabled"
}

msg_info "Detecting virtualization environment"
detected=$(systemd-detect-virt --vm 2>/dev/null || echo "unknown")
msg_ok "Detected virtualization: ${detected}"

case "${detected}" in
  kvm|qemu)
    install_package_if_missing "qemu-guest-agent"
    enable_services "qemu-guest-agent.service"
    ensure_serial_console
    ;;
  vmware)
    install_package_if_missing "open-vm-tools"
    enable_services "open-vm-tools.service"
    ;;
  microsoft)
    install_package_if_missing "hyperv-daemons"
    enable_services \
      "hv-kvp-daemon.service" \
      "hv-fcopy-daemon.service" \
      "hv-vss-daemon.service"
    ;;
  oracle)
    install_package_if_missing "virtualbox-guest-utils"
    enable_services "vboxservice.service"
    ;;
  none)
    msg_ok "Bare metal detected; no guest agent required"
    exit 0
    ;;
  *)
    msg_error "Unsupported virtualization type '${detected}'."
    exit 1
    ;;
esac

msg_ok "Guest agent configuration finished"
