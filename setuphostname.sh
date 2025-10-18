#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

HOSTS_FILE="/etc/hosts"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/raffo-domains.conf"

escape_regex() {
  printf '%s' "$1" | sed -e 's/[][\\.^$*+?|(){}-]/\\&/g'
}

is_valid_hostname() {
  local host="$1"
  if [[ -z "$host" ]]; then
    return 1
  fi
  if (( ${#host} > 253 )); then
    return 1
  fi
  if [[ "$host" == "." ]]; then
    return 1
  fi
  IFS='.' read -ra PARTS <<<"$host"
  for part in "${PARTS[@]}"; do
    if [[ -z "$part" ]]; then
      return 1
    fi
    if (( ${#part} > 63 )); then
      return 1
    fi
    if [[ ! "$part" =~ ^[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?$ ]]; then
      return 1
    fi
  done
  return 0
}

primary_ipv4() {
  ip -4 addr show scope global up 2>/dev/null |
    awk '/inet / {print $2}' | head -n1 | cut -d'/' -f1
}

update_hosts_entry() {
  local ip="$1"; shift
  local names="$1"
  [[ -n "$ip" ]] || return 0
  local regex
  regex="^$(escape_regex "$ip")[[:space:]]+"
  if grep -Eq "$regex" "$HOSTS_FILE"; then
    sed -i -E "s/${regex}.*/$ip\t$names/" "$HOSTS_FILE"
    msg_ok "Updated $HOSTS_FILE entry for $ip"
  else
    printf '%s\t%s\n' "$ip" "$names" >>"$HOSTS_FILE"
    msg_ok "Added $HOSTS_FILE entry for $ip"
  fi
}

configure_search_domain() {
  local suffix="$1"
  if [[ -z "$suffix" ]]; then
    return 0
  fi

  if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    mkdir -p "$(dirname "$RESOLVED_DROPIN")"
    if [[ -f "$RESOLVED_DROPIN" ]]; then
      local backup
      backup="$(raffo_backup "$RESOLVED_DROPIN" "resolved-domain.conf")"
      [[ -z "$backup" ]] || msg_info "Backup of $RESOLVED_DROPIN saved to $backup"
    fi
    printf '[Resolve]\nDomains=%s\n' "$suffix" >"$RESOLVED_DROPIN"
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
      if systemctl restart systemd-resolved >/dev/null 2>&1; then
        msg_ok "Configured systemd-resolved search domain: $suffix"
        return 0
      fi
      msg_error "Failed to restart systemd-resolved; please restart manually"
      return 1
    else
      msg_info "systemd-resolved inactive; configuration will apply on next start"
      return 0
    fi
  fi

  if [[ -f /etc/resolv.conf ]]; then
    local backup
    backup="$(raffo_backup /etc/resolv.conf "resolv.conf")"
    [[ -z "$backup" ]] || msg_info "Backup of /etc/resolv.conf saved to $backup"
    if grep -Eq '^\s*search\b' /etc/resolv.conf; then
      sed -i -E "s/^\s*search\b.*/search $suffix/" /etc/resolv.conf
    else
      printf '\nsearch %s\n' "$suffix" >>/etc/resolv.conf
    fi
    msg_ok "Updated /etc/resolv.conf search suffix"
    return 0
  fi

  msg_error "No resolver configuration available to update search suffix"
  return 1
}

if ! command -v hostnamectl >/dev/null 2>&1; then
  msg_error "hostnamectl not available"
  exit 1
fi

current_hostname="$(hostnamectl --static 2>/dev/null || hostname 2>/dev/null || echo "")"
current_hostname="${current_hostname:-$(hostname 2>/dev/null || echo "")}" 
msg_info "Current hostname: ${current_hostname:-unknown}"

target_hostname=""
while true; do
  if ! input=$(ask_input "Hostname" "Enter new hostname or FQDN (leave blank to keep current)" "$current_hostname"); then
    input=""
  fi
  input="$(raffo_trim "${input:-}")"
  if [[ -z "$input" ]]; then
    target_hostname="$current_hostname"
    break
  fi
  lower="${input,,}"
  if is_valid_hostname "$lower"; then
    target_hostname="$lower"
    break
  fi
  show_message "Hostname" "Hostname must comply with RFC 1123 (letters, digits, hyphens, 1-63 chars per label)."
done

if [[ -z "$target_hostname" ]]; then
  msg_error "Unable to determine hostname"
  exit 1
fi

if [[ "$target_hostname" == "$current_hostname" ]]; then
  msg_info "Hostname unchanged"
else
  msg_info "Setting hostname to $target_hostname"
  hostnamectl set-hostname "$target_hostname"
  msg_ok "Hostname updated to $target_hostname"
fi

short_hostname="${target_hostname%%.*}"
if [[ -z "$short_hostname" ]]; then
  short_hostname="$target_hostname"
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
  touch "$HOSTS_FILE"
fi

hosts_backup="$(raffo_backup "$HOSTS_FILE" "hosts")"
[[ -z "$hosts_backup" ]] || msg_info "Backup of $HOSTS_FILE saved to $hosts_backup"

host_entries="$target_hostname"
if [[ "$short_hostname" != "$target_hostname" ]]; then
  host_entries="$host_entries $short_hostname"
fi

msg_info "Updating $HOSTS_FILE for loopback"
update_hosts_entry "127.0.1.1" "$host_entries"

primary_ip="$(primary_ipv4)"
if [[ -n "$primary_ip" ]]; then
  msg_info "Updating $HOSTS_FILE for $primary_ip"
  update_hosts_entry "$primary_ip" "$host_entries"
else
  msg_info "No primary IPv4 detected; skipping non-loopback hosts entry"
fi

default_suffix=""
if [[ "$target_hostname" == *.* ]]; then
  default_suffix="${target_hostname#*.}"
fi

if ask_yesno "DNS Search Suffix" "Configure DNS search suffix?"; then
  suffix_prompt="Enter DNS search suffix"
  if [[ -n "$default_suffix" ]]; then
    suffix_prompt+=" (leave blank to use $default_suffix)"
  fi
  if ! suffix_input=$(ask_input "DNS Search Suffix" "$suffix_prompt" "$default_suffix"); then
    suffix_input="$default_suffix"
  fi
  suffix_input="$(raffo_trim "${suffix_input:-}")"
  if [[ -z "$suffix_input" ]]; then
    suffix_input="$default_suffix"
  fi
  suffix_input="${suffix_input,,}"
  if [[ -n "$suffix_input" ]]; then
    if is_valid_hostname "$suffix_input"; then
      if ! configure_search_domain "$suffix_input"; then
        msg_error "DNS search suffix configuration encountered issues"
      fi
    else
      show_message "DNS Search Suffix" "Search suffix must be a valid domain; skipping configuration."
    fi
  else
    msg_info "No suffix provided; skipping configuration"
  fi
else
  msg_info "DNS search suffix unchanged"
fi

msg_ok "Hostname configuration complete"
