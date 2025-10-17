#!/usr/bin/env bash
set -euo pipefail
source /root/raffolib.sh

CONFIG_FILE="/etc/ssh/sshd_config"
SSH_PORT_STATE_FILE="$RAFFO_STATE_DIR/ssh_port"

if [[ ! -f "$CONFIG_FILE" ]]; then
  msg_error "sshd_config not found"
  exit 1
fi

if BACKUP_PATH=$(raffo_backup "$CONFIG_FILE" "sshd_config" 2>/dev/null); then
  msg_ok "Backup stored at $BACKUP_PATH"
else
  msg_info "Continuing without new backup (prior copy may already exist)"
fi

python_edit() {
  local script="$1"
  shift
  python3 - "$script" "$@" <<'PY'
import os
import re
import sys

script = sys.argv[1]
config_path = sys.argv[2]
args = sys.argv[3:]


def load_lines():
    with open(config_path, 'r', encoding='utf-8') as fh:
        return fh.readlines()


def save_lines(lines):
    tmp_path = config_path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as fh:
        fh.writelines(lines)
    os.replace(tmp_path, config_path)


def find_match_index(lines):
    for idx, line in enumerate(lines):
        if line.lstrip().startswith('Match '):
            return idx
    return None


def set_option(key, value):
    lines = load_lines()
    pattern = re.compile(r'^\s*#?\s*' + re.escape(key) + r'\b', re.IGNORECASE)
    match_index = find_match_index(lines)
    search_end = match_index if match_index is not None else len(lines)
    for idx in range(search_end):
        if pattern.match(lines[idx]):
            lines[idx] = f"{key} {value}\n"
            save_lines(lines)
            return
    insert_at = search_end
    if insert_at > 0 and lines[insert_at - 1].strip():
        lines.insert(insert_at, "\n")
        insert_at += 1
    lines.insert(insert_at, f"{key} {value}\n")
    save_lines(lines)


def remove_option(key):
    lines = load_lines()
    pattern = re.compile(r'^\s*#?\s*' + re.escape(key) + r'\b', re.IGNORECASE)
    match_index = find_match_index(lines)
    search_end = match_index if match_index is not None else len(lines)
    new_lines = []
    removed = False
    for idx, line in enumerate(lines):
        if idx < search_end and pattern.match(line):
            removed = True
            continue
        new_lines.append(line)
    if removed:
        save_lines(new_lines)


def get_option(key):
    lines = load_lines()
    pattern = re.compile(r'^\s*#?\s*' + re.escape(key) + r'\b', re.IGNORECASE)
    match_index = find_match_index(lines)
    search_end = match_index if match_index is not None else len(lines)
    for idx in range(search_end):
        if pattern.match(lines[idx]):
            parts = lines[idx].strip().split(None, 1)
            if len(parts) > 1:
                return parts[1]
            return ''
    return ''


if script == 'set':
    key, value = args
    set_option(key, value)
elif script == 'remove':
    key = args[0]
    remove_option(key)
elif script == 'get':
    key = args[0]
    value = get_option(key)
    if value:
        sys.stdout.write(value)
else:
    raise SystemExit(f'Unsupported operation: {script}')
PY
}

set_global_option() {
  local key="$1" value="$2"
  python_edit set "$CONFIG_FILE" "$key" "$value"
}

remove_global_option() {
  local key="$1"
  python_edit remove "$CONFIG_FILE" "$key"
}

get_global_option() {
  local key="$1"
  python_edit get "$CONFIG_FILE" "$key"
}

restart_ssh() {
  if ! sshd -t -f "$CONFIG_FILE"; then
    msg_error "sshd configuration check failed"
    return 1
  fi

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
      msg_ok "sshd restarted"
      return 0
    fi
  fi

  if service sshd restart 2>/dev/null || service ssh restart 2>/dev/null; then
    msg_ok "sshd restarted"
    return 0
  fi

  msg_error "Failed to restart sshd; please restart manually"
  return 1
}

ensure_firewall_ssh_port() {
  local port="$1"
  [[ -n "$port" ]] || return 0

  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  local active_fw=""
  for svc in ufw firewalld nftables iptables; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      active_fw="$svc"
      break
    fi
  done

  [[ -n "$active_fw" ]] || return 0

  case "$active_fw" in
    ufw)
      ufw allow "$port/tcp" >/dev/null 2>&1 &&
        msg_ok "Ensured $port/tcp allowed via ufw"
      ;;
    firewalld)
      firewall-cmd --add-port="$port/tcp" --permanent >/dev/null 2>&1 &&
        firewall-cmd --reload >/dev/null 2>&1 &&
        msg_ok "Ensured $port/tcp allowed via firewalld"
      ;;
    nftables)
      if ! nft list chain inet filter input 2>/dev/null | grep -Eq "tcp dport ${port} .*accept"; then
        nft add rule inet filter input tcp dport "$port" counter accept >/dev/null 2>&1 &&
          msg_ok "Ensured $port/tcp allowed via nftables"
      fi
      ;;
    iptables)
      if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 &&
          msg_ok "Ensured $port/tcp allowed via iptables"
      fi
      ;;
  esac
}

persist_ssh_port() {
  local port="$1"
  [[ -n "$port" ]] || return
  mkdir -p "$RAFFO_STATE_DIR"
  echo "$port" > "$SSH_PORT_STATE_FILE"
}

current_port() {
  local configured
  configured=$(get_global_option "Port")
  if [[ -n "$configured" ]]; then
    echo "$configured"
  else
    echo "22"
  fi
}

# Record the active port so the firewall module can keep it open.
persist_ssh_port "$(current_port)"

ensure_authorized_keys() {
  local user="$1" key="$2"
  local user_home
  user_home=$(getent passwd "$user" | cut -d: -f6)
  [[ -n "$user_home" ]] || return 1
  local ssh_dir="$user_home/.ssh"
  install -d -m 700 -o "$user" -g "$user" "$ssh_dir"
  local auth_file="$ssh_dir/authorized_keys"
  touch "$auth_file"
  chown "$user":"$user" "$auth_file"
  chmod 600 "$auth_file"
  if grep -Fxq "$key" "$auth_file"; then
    msg_error "Key already present for $user"
  else
    echo "$key" >> "$auth_file"
    chown "$user":"$user" "$auth_file"
    msg_ok "Key added for $user"
  fi
}

enforce_key_authentication() {
  set_global_option "PubkeyAuthentication" "yes"
  set_global_option "PasswordAuthentication" "no"
  set_global_option "ChallengeResponseAuthentication" "no"
  set_global_option "KbdInteractiveAuthentication" "no"
  set_global_option "AuthenticationMethods" "publickey"
}

configure_allowlist() {
  local directive="$1"
  local label="$2"
  local current_value
  current_value=$(get_global_option "$directive")
  local new_value
  if ! new_value=$(ask_input "$label" "Space-separated entries (leave blank to clear)" "$current_value"); then
    msg_info "$directive unchanged"
    return
  fi
  if [[ -n "$new_value" ]]; then
    set_global_option "$directive" "$new_value"
    msg_ok "$directive set"
    restart_ssh
  else
    remove_global_option "$directive"
    msg_ok "$directive cleared"
    restart_ssh
  fi
}

configure_keepalive() {
  local current_interval current_count current_tcp
  current_interval=$(get_global_option "ClientAliveInterval")
  current_count=$(get_global_option "ClientAliveCountMax")
  current_tcp=$(get_global_option "TCPKeepAlive")
  current_interval=${current_interval:-0}
  current_count=${current_count:-3}
  current_tcp=${current_tcp:-yes}

  local new_interval
  if ! new_interval=$(ask_input "ClientAliveInterval" "Seconds before sending keepalive (0 disables)" "$current_interval"); then
    msg_info "Keepalive settings unchanged"
    return
  fi
  local new_count
  if ! new_count=$(ask_input "ClientAliveCountMax" "Disconnect after this many unanswered keepalives" "$current_count"); then
    msg_info "Keepalive settings unchanged"
    return
  fi
  local tcp_choice
  if ! tcp_choice=$(ask_menu "TCPKeepAlive" "Current setting: $current_tcp" \
    "yes" "Enable TCP keepalive probes" \
    "no" "Disable TCP keepalive probes"); then
    msg_info "Keepalive settings unchanged"
    return
  fi

  if [[ -n "$new_interval" ]]; then
    set_global_option "ClientAliveInterval" "$new_interval"
  else
    remove_global_option "ClientAliveInterval"
  fi

  if [[ -n "$new_count" ]]; then
    set_global_option "ClientAliveCountMax" "$new_count"
  else
    remove_global_option "ClientAliveCountMax"
  fi

  if [[ -n "$tcp_choice" ]]; then
    set_global_option "TCPKeepAlive" "$tcp_choice"
  fi

  msg_ok "Keepalive settings updated"
  restart_ssh
}

while true; do
  choice=$(ask_menu "SSH Hardening" \
    "Select an action" \
    "port" "Change SSH port" \
    "root" "Configure root login" \
    "password" "Toggle password authentication" \
    "enforce" "Enforce key-based authentication" \
    "allowusers" "Set AllowUsers" \
    "allowgroups" "Set AllowGroups" \
    "keepalive" "Tune keepalive behavior" \
    "key" "Add an authorized key" \
    "summ" "Show current settings" \
    "done" "Return to main menu") || choice="done"

  case "$choice" in
    port)
      current_port_value=$(current_port)
      new_port=$(ask_input "SSH Port" "Enter new SSH port" "$current_port_value") || new_port=""
      if [[ -n "$new_port" && "$new_port" != "$current_port_value" ]]; then
        msg_info "Setting SSH port to $new_port"
        set_global_option "Port" "$new_port"
        persist_ssh_port "$new_port"
        ensure_firewall_ssh_port "$new_port"
        restart_ssh
      else
        msg_info "Port unchanged"
      fi
      ;;
    root)
      current_setting=$(get_global_option "PermitRootLogin")
      current_setting=${current_setting:-prohibit-password}
      toggle=$(ask_menu "Root Login" \
        "Current PermitRootLogin: $current_setting" \
        "no" "Disable root SSH login" \
        "prohibit-password" "Allow key auth only" \
        "yes" "Allow all root logins") || toggle=""
      if [[ -n "$toggle" && "$toggle" != "$current_setting" ]]; then
        set_global_option "PermitRootLogin" "$toggle"
        msg_ok "PermitRootLogin set to $toggle"
        restart_ssh
      else
        msg_info "Root login setting unchanged"
      fi
      ;;
    password)
      current_password=$(get_global_option "PasswordAuthentication")
      current_password=${current_password:-yes}
      new_password=$(ask_menu "Password Authentication" \
        "Current setting: $current_password" \
        "no" "Disable password authentication" \
        "yes" "Enable password authentication") || new_password=""
      if [[ -n "$new_password" && "$new_password" != "$current_password" ]]; then
        set_global_option "PasswordAuthentication" "$new_password"
        if [[ "$new_password" == "yes" ]]; then
          current_methods=$(get_global_option "AuthenticationMethods")
          if [[ "$current_methods" == "publickey" ]]; then
            remove_global_option "AuthenticationMethods"
            msg_info "AuthenticationMethods restriction cleared"
          fi
          for directive in ChallengeResponseAuthentication KbdInteractiveAuthentication; do
            if [[ "$(get_global_option "$directive")" == "no" ]]; then
              remove_global_option "$directive"
              msg_info "$directive restored to default"
            fi
          done
        fi
        msg_ok "PasswordAuthentication set to $new_password"
        restart_ssh
      else
        msg_info "PasswordAuthentication unchanged"
      fi
      ;;
    enforce)
      enforce_key_authentication
      msg_ok "Password logins disabled; keys required"
      restart_ssh
      ;;
    allowusers)
      configure_allowlist "AllowUsers" "AllowUsers"
      ;;
    allowgroups)
      configure_allowlist "AllowGroups" "AllowGroups"
      ;;
    keepalive)
      configure_keepalive
      ;;
    key)
      menu_args=("root" " ")
      while IFS=: read -r name _ uid _; do
        (( uid >= 1000 )) || continue
        menu_args+=("$name" " ")
      done < /etc/passwd
      target=$(ask_menu "Select Account" "Choose user for key installation" "${menu_args[@]}") || continue
      pubkey=$(ask_input "Public Key" "Paste the SSH public key" "") || pubkey=""
      if [[ -n "$pubkey" ]]; then
        ensure_authorized_keys "$target" "$pubkey"
      else
        msg_info "No key provided"
      fi
      ;;
    summ)
      echo
      echo "Current SSH configuration overview:"
      for directive in Port PermitRootLogin PasswordAuthentication AuthenticationMethods AllowUsers AllowGroups ClientAliveInterval ClientAliveCountMax TCPKeepAlive; do
        value=$(get_global_option "$directive")
        if [[ -n "$value" ]]; then
          printf '%s %s\n' "$directive" "$value"
        fi
      done
      echo
      read -p "Press Enter to continue" _
      ;;
    *)
      break
      ;;
  esac

done

msg_ok "SSH configuration complete"
