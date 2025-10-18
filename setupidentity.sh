#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

summary=()
add_summary() {
  summary+=("$1")
}

require_command() {
  local cmd="$1" msg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    msg_error "$msg"
    exit 1
  fi
}

msg_info "Regenerating machine-id"
rm -f /etc/machine-id
rm -f /var/lib/dbus/machine-id
install -d -m 0755 /var/lib/dbus
require_command "systemd-machine-id-setup" "systemd-machine-id-setup not available"
if ! systemd-machine-id-setup >/dev/null 2>&1; then
  msg_error "Failed to run systemd-machine-id-setup"
  exit 1
fi
if [[ -d /var/lib/dbus && ! -e /var/lib/dbus/machine-id ]]; then
  ln -s /etc/machine-id /var/lib/dbus/machine-id
fi
msg_ok "Machine-id regenerated"
add_summary "Machine-id refreshed"

msg_info "Regenerating SSH host keys"
rm -f /etc/ssh/ssh_host_*
regenerated_keys=0
if command -v dpkg-reconfigure >/dev/null 2>&1; then
  if DEBIAN_FRONTEND=noninteractive dpkg-reconfigure openssh-server >/dev/null 2>&1; then
    regenerated_keys=1
  fi
fi
if [[ $regenerated_keys -eq 0 ]]; then
  require_command "ssh-keygen" "ssh-keygen not available"
  declare -A keygen_args=(
    [rsa]="-t rsa -b 4096"
    [ed25519]="-t ed25519"
    [ecdsa]="-t ecdsa -b 521"
  )
  for key_type in rsa ed25519 ecdsa; do
    args="${keygen_args[$key_type]}"
    if ! ssh-keygen -q ${args} -N "" -f "/etc/ssh/ssh_host_${key_type}_key" >/dev/null 2>&1; then
      msg_error "Failed to generate ${key_type} host key"
      exit 1
    fi
  done
fi
msg_ok "SSH host keys regenerated"
add_summary "SSH host keys renewed"

msg_info "Reseeding systemd random seed"
rm -f /var/lib/systemd/random-seed
install -d -m 0700 /var/lib/systemd
if command -v systemd-random-seed >/dev/null 2>&1; then
  if ! systemd-random-seed >/dev/null 2>&1; then
    msg_error "systemd-random-seed command failed"
    exit 1
  fi
elif command -v openssl >/dev/null 2>&1; then
  if ! openssl rand -out /var/lib/systemd/random-seed 512 >/dev/null 2>&1; then
    msg_error "openssl rand failed"
    exit 1
  fi
else
  msg_error "No tool available to reseed random seed"
  exit 1
fi
chmod 600 /var/lib/systemd/random-seed
msg_ok "Random seed reset"
add_summary "Random seed reseeded"

msg_info "Clearing network leases"
leases_cleared=0
for lease_dir in /var/lib/dhcp /var/lib/dhcp3 /var/lib/NetworkManager; do
  if [[ -d "$lease_dir" ]]; then
    find "$lease_dir" -type f -name '*lease*' -delete
    leases_cleared=1
  fi
done
if [[ $leases_cleared -eq 1 ]]; then
  msg_ok "DHCP leases cleared"
  add_summary "DHCP leases cleared"
else
  msg_ok "No DHCP lease files present"
  add_summary "No DHCP leases found"
fi

msg_info "Removing installer and cloud-init state"
for installer_path in /var/log/installer /var/log/anaconda /var/log/subiquity; do
  if [[ -d "$installer_path" ]]; then
    find "$installer_path" -mindepth 1 -delete
  fi
  if [[ -f "$installer_path" ]]; then
    : >"$installer_path"
  fi
done
for cloud_file in /var/log/cloud-init.log /var/log/cloud-init-output.log; do
  if [[ -f "$cloud_file" ]]; then
    : >"$cloud_file"
  fi
done
if [[ -d /var/lib/cloud ]]; then
  find /var/lib/cloud -mindepth 1 -delete
fi
msg_ok "Installer history cleared"
add_summary "Installer and cloud-init state cleared"

echo
printf '%s\n' "Summary:"
for entry in "${summary[@]}"; do
  printf ' - %s\n' "$entry"
done

msg_ok "Identity reset completed"
exit 0
