#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

APT_UPDATED=0
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
ensure_packages() {
  local packages=("$@")
  local missing=()
  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  if [[ $APT_UPDATED -eq 0 ]]; then
    msg_info "Refreshing package metadata"
    apt-get update -y >/tmp/raffo_apt_update.log 2>&1 || {
      msg_error "apt-get update failed"
      cat /tmp/raffo_apt_update.log
      exit 1
    }
    APT_UPDATED=1
    msg_ok "Package metadata refreshed"
  fi
  msg_info "Installing packages: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/tmp/raffo_pkg_install.log 2>&1 || {
    msg_error "Package installation failed"
    cat /tmp/raffo_pkg_install.log
    exit 1
  }
  msg_ok "Packages installed"
}

apply_sysctl_setting() {
  local key="$1" value="$2"
  sysctl -w "$key=$value" >/dev/null
}

msg_info "Applying kernel sysctl hardening"
raffo_backup "/etc/sysctl.conf" "sysctl.conf" >/dev/null 2>&1 || true
SYSCTL_HARDEN_FILE="/etc/sysctl.d/99-raffo-hardening.conf"
if [[ -f "$SYSCTL_HARDEN_FILE" ]]; then
  raffo_backup "$SYSCTL_HARDEN_FILE" "99-raffo-hardening.conf" >/dev/null 2>&1 || true
fi
cat >"$SYSCTL_HARDEN_FILE" <<'HARDEN'
# Managed by Raffo Setup (setuphardening.sh)
# Kernel network hardening defaults
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
HARDEN
apply_sysctl_setting "net.ipv4.conf.all.rp_filter" 1
apply_sysctl_setting "net.ipv4.conf.default.rp_filter" 1
apply_sysctl_setting "net.ipv4.conf.all.accept_redirects" 0
apply_sysctl_setting "net.ipv4.conf.default.accept_redirects" 0
apply_sysctl_setting "net.ipv6.conf.all.accept_redirects" 0
apply_sysctl_setting "net.ipv6.conf.default.accept_redirects" 0
apply_sysctl_setting "net.ipv4.tcp_syncookies" 1
apply_sysctl_setting "net.ipv4.conf.all.log_martians" 1
apply_sysctl_setting "net.ipv4.conf.default.log_martians" 1
msg_ok "Kernel sysctl parameters updated"

read -rp "Disable IPv6 system-wide? [y/N]: " DISABLE_IPV6
IPV6_FILE="/etc/sysctl.d/99-raffo-ipv6.conf"
if [[ -f "$IPV6_FILE" ]]; then
  raffo_backup "$IPV6_FILE" "99-raffo-ipv6.conf" >/dev/null 2>&1 || true
fi
if [[ "$DISABLE_IPV6" =~ ^[Yy]$ ]]; then
  cat >"$IPV6_FILE" <<'IPCONF'
# Managed by Raffo Setup (setuphardening.sh)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
IPCONF
  apply_sysctl_setting "net.ipv6.conf.all.disable_ipv6" 1
  apply_sysctl_setting "net.ipv6.conf.default.disable_ipv6" 1
  msg_ok "IPv6 disabled via sysctl"
else
  cat >"$IPV6_FILE" <<'IPCONF'
# Managed by Raffo Setup (setuphardening.sh)
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
IPCONF
  apply_sysctl_setting "net.ipv6.conf.all.disable_ipv6" 0
  apply_sysctl_setting "net.ipv6.conf.default.disable_ipv6" 0
  msg_ok "IPv6 remains enabled"
fi

msg_info "Ensuring AppArmor profiles are enforced"
ensure_packages apparmor apparmor-utils
systemctl enable --now apparmor >/dev/null 2>&1 || true
if command -v aa-enforce >/dev/null 2>&1; then
  aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet apparmor; then
  msg_ok "AppArmor service active"
else
  msg_error "AppArmor service not active"
fi

msg_info "Installing and tuning fail2ban"
ensure_packages fail2ban
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [[ -f "$JAIL_LOCAL" ]]; then
  raffo_backup "$JAIL_LOCAL" "fail2ban-jail.local" >/dev/null 2>&1 || true
fi
cat >"$JAIL_LOCAL" <<JAIL
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
destemail = root@localhost
sender = fail2ban@${HOSTNAME_FQDN}

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 4
JAIL
systemctl enable --now fail2ban >/dev/null 2>&1
systemctl reload fail2ban >/dev/null 2>&1 || true
msg_ok "fail2ban configured"

msg_info "Deploying login banners"
for banner in /etc/issue /etc/issue.net; do
  if [[ -f "$banner" ]]; then
    raffo_backup "$banner" "$(basename "$banner")" >/dev/null 2>&1 || true
  fi
  cat >"$banner" <<'BANNER'
******************************************************************
*  WARNING: Authorized access only. Activities may be monitored.  *
*  Disconnect immediately if you are not an authorized user.      *
******************************************************************
BANNER
  chmod 0644 "$banner"
done
msg_ok "Login banners updated"

msg_info "Reviewing enabled services for potential disablement"
mapfile -t ENABLED_SERVICES < <(systemctl list-unit-files --state=enabled --type=service --no-legend 2>/dev/null | awk '{print $1}' | sort -u)
ESSENTIAL_PREFIXES=(
  "systemd-"
  "dbus"
  "getty@"
  "console-setup"
  "network"
  "ssh"
  "cron"
  "rsyslog"
  "fail2ban"
  "apparmor"
)
should_skip_service() {
  local svc="$1"
  for prefix in "${ESSENTIAL_PREFIXES[@]}"; do
    if [[ "$svc" == "$prefix"* ]]; then
      return 0
    fi
  done
  case "$svc" in
    "cloud-init.service"|"ufw.service"|"firewalld.service"|"nftables.service"|"iptables.service")
      return 0
      ;;
  esac
  return 1
}

for svc in "${ENABLED_SERVICES[@]}"; do
  if should_skip_service "$svc"; then
    continue
  fi
  read -rp "Disable service $svc ? [y/N]: " disable_choice
  if [[ "$disable_choice" =~ ^[Yy]$ ]]; then
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    echo "   -> $svc disabled"
  fi
done
msg_ok "Service review complete"

msg_info "Running Lynis audit"
ensure_packages lynis
mkdir -p /var/log/raffosetup
LYNIS_LOG="/var/log/raffosetup/lynis-$(raffo_timestamp).log"
set +e
lynis audit system | tee "$LYNIS_LOG"
LYNIS_RC=${PIPESTATUS[0]}
set -e
if [[ $LYNIS_RC -ne 0 ]]; then
  msg_error "Lynis audit failed (exit $LYNIS_RC)"
  exit $LYNIS_RC
fi
if [[ -f /var/log/lynis-report.dat ]]; then
  cp /var/log/lynis-report.dat "/var/log/raffosetup/lynis-report-$(raffo_timestamp).dat"
fi
msg_ok "Lynis audit report stored at /var/log/raffosetup"

msg_ok "System hardening complete"
