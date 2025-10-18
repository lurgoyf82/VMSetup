#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if [[ $EUID -ne 0 ]]; then
  msg_error "This helper must be run as root"
  exit 1
fi

valid_username() {
  local name="$1"
  [[ "$name" =~ ^[a-z_][a-z0-9_-]*$ ]] && [[ ${#name} -le 32 ]]
}

create_user() {
  local username="$1"
  local full_name="$2"

  if id "$username" &>/dev/null; then
    msg_error "User $username already exists"
    return 1
  fi

  msg_info "Creating user $username"
  useradd -m -s /bin/bash -c "$full_name" "$username"
  passwd "$username"
  usermod -aG sudo "$username"
  msg_ok "User $username created and added to sudo"
}

copy_authorized_keys() {
  local username="$1" source_file="$2"
  if [[ ! -f "$source_file" ]]; then
    msg_error "Authorized keys file $source_file not found"
    return 1
  fi
  local home_dir
  home_dir=$(getent passwd "$username" | cut -d: -f6)
  if [[ -z "$home_dir" ]]; then
    msg_error "Unable to determine home directory for $username"
    return 1
  fi
  local ssh_dir="$home_dir/.ssh"
  install -d -m 700 -o "$username" -g "$username" "$ssh_dir"
  local dest_file="$ssh_dir/authorized_keys"
  install -m 600 -o "$username" -g "$username" "$source_file" "$dest_file"
  msg_ok "Copied authorized_keys to $dest_file"
}

configure_sudoers_dropin() {
  local username="$1"
  local choice
  choice=$(ask_menu "Sudo Policy" \
    "Choose sudo policy for $username" \
    "require" "Require password on sudo" \
    "nopass" "Passwordless sudo" \
    "timeout" "Require password with custom timeout") || choice="require"

  local tmp_file
  tmp_file=$(mktemp)
  {
    echo "# Managed by Raffo Setup"
    echo "# $(date --iso-8601=seconds)"
    case "$choice" in
      nopass)
        echo "$username ALL=(ALL:ALL) NOPASSWD:ALL"
        ;;
      timeout)
        local timeout_value
        timeout_value=$(ask_input "Sudo Timeout" "Enter timestamp_timeout in minutes" "15") || timeout_value="15"
        [[ "$timeout_value" =~ ^[0-9]+$ ]] || timeout_value="15"
        echo "Defaults:${username} timestamp_timeout=${timeout_value}"
        echo "$username ALL=(ALL:ALL) ALL"
        ;;
      *)
        echo "$username ALL=(ALL:ALL) ALL"
        ;;
    esac
  } >"$tmp_file"

  if visudo -cf "$tmp_file"; then
    install -m 440 -o root -g root "$tmp_file" "/etc/sudoers.d/90-raffo-${username}"
    msg_ok "Sudoers drop-in configured"
  else
    msg_error "visudo validation failed; drop-in not installed"
  fi
  rm -f "$tmp_file"
}

enforce_password_age() {
  local username="$1"
  local max_days min_days warn_days
  max_days=$(ask_input "Password Expiry" "Maximum days before password change" "90") || max_days="90"
  min_days=$(ask_input "Password Expiry" "Minimum days between password changes" "7") || min_days="7"
  warn_days=$(ask_input "Password Expiry" "Warning days before expiry" "14") || warn_days="14"
  [[ "$max_days" =~ ^[0-9]+$ ]] || max_days="90"
  [[ "$min_days" =~ ^[0-9]+$ ]] || min_days="7"
  [[ "$warn_days" =~ ^[0-9]+$ ]] || warn_days="14"
  chage -M "$max_days" -m "$min_days" -W "$warn_days" "$username"
  msg_ok "Password aging policy applied"
}

ensure_pwquality() {
  local pam_file="/etc/pam.d/common-password"
  msg_info "Ensuring libpam-pwquality is installed"
  if ! dpkg -s libpam-pwquality &>/dev/null; then
    apt-get update
    apt-get install -y libpam-pwquality
  fi
  local backup
  backup=$(raffo_backup "$pam_file" "common-password") || backup=""
  [[ -n "$backup" ]] && msg_ok "Backup created at $backup"

  if grep -Eq '^password\s+requisite\s+pam_pwquality.so' "$pam_file"; then
    sed -ri 's#^password\s+requisite\s+pam_pwquality\.so.*#password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1#g' "$pam_file"
  else
    sed -i '1ipassword requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' "$pam_file"
  fi
  msg_ok "Updated PAM pwquality policy"
}

lock_root_account() {
  if passwd -S root | grep -q '^root L'; then
    msg_info "Root account already locked"
  else
    passwd -l root
    msg_ok "Root account locked"
  fi
}

main() {
  if ! ask_yesno "Create User" "Create a new sudo-enabled user?"; then
    msg_ok "User creation skipped"
    return 200
  fi

  local username full_name
  while true; do
    username=$(ask_input "Username" "Enter username for the new account" "") || username=""
    username=${username,,}
    username=${username// /}
    if [[ -z "$username" ]]; then
      msg_error "Username cannot be empty"
      continue
    fi
    if ! valid_username "$username"; then
      msg_error "Invalid username. Use lowercase letters, digits, underscores, or hyphens"
      continue
    fi
    if id "$username" &>/dev/null; then
      msg_error "User $username already exists"
      continue
    fi
    break
  done

  full_name=$(ask_input "Full Name" "Enter the user's full name" "") || full_name=""
  create_user "$username" "$full_name"

  local auth_source
  if ask_yesno "SSH Keys" "Copy existing authorized_keys to the new user?"; then
    auth_source=$(ask_input "authorized_keys" "Path to authorized_keys file" "/root/.ssh/authorized_keys") || auth_source=""
    if [[ -n "$auth_source" ]]; then
      copy_authorized_keys "$username" "$auth_source"
    else
      msg_info "No authorized_keys path provided"
    fi
  fi

  configure_sudoers_dropin "$username"

  if ask_yesno "Password Aging" "Enforce password expiry for $username?"; then
    enforce_password_age "$username"
  fi

  if ask_yesno "Password Quality" "Require strong passwords via PAM pwquality?"; then
    ensure_pwquality
  fi

  if ask_yesno "Lock Root" "Lock the root account after provisioning?"; then
    lock_root_account
  fi

  msg_ok "User provisioning complete"
}

main "$@"
