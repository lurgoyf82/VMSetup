#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if [[ $EUID -ne 0 ]]; then
  msg_error "Logging configuration requires root"
  exit 1
fi

umask 022

CONFIG_DIR="/etc/systemd/journald.conf.d"
DROPIN_FILE="$CONFIG_DIR/raffo.conf"
PERSIST_DIR="/var/log/journal"
RSYSLOG_CONF="/etc/rsyslog.d/raffo-remote.conf"
JOURNAL_UPLOAD_DIR="/etc/systemd/journal-upload.conf.d"
JOURNAL_UPLOAD_CONF="$JOURNAL_UPLOAD_DIR/raffo.conf"
SUMMARY=()
services_to_restart=("systemd-journald")

trim() {
  local value="$1"
  printf '%s\n' "$value" | awk '{$1=$1; print}'
}

contains_inline_credentials() {
  local value="$1"
  if [[ "$value" =~ ://[^/]*:[^@]*@ ]]; then
    return 0
  fi
  if [[ "$value" =~ [^[:space:]@]+:[^[:space:]@]+@ ]]; then
    return 0
  fi
  return 1
}

current_dropin_value() {
  local key="$1" default_value="$2"
  if [[ -f "$DROPIN_FILE" ]]; then
    local line
    line=$(grep -E "^[[:space:]]*${key}=" "$DROPIN_FILE" | tail -n1 || true)
    if [[ -n "$line" ]]; then
      line="${line#*=}"
      line="$(trim "$line")"
      if [[ -n "$line" ]]; then
        echo "$line"
        return
      fi
    fi
  fi
  echo "$default_value"
}

current_rsyslog_target() {
  if [[ -f "$RSYSLOG_CONF" ]]; then
    local line
    line=$(grep -Ev '^[[:space:]]*#' "$RSYSLOG_CONF" | grep -E '@@?' | tail -n1 || true)
    if [[ -n "$line" ]]; then
      line=$(echo "$line" | awk '{print $2}')
      line="$(trim "$line")"
      echo "$line"
      return
    fi
  fi
  echo ""
}

current_journal_url() {
  if [[ -f "$JOURNAL_UPLOAD_CONF" ]]; then
    local line
    line=$(grep -E '^[[:space:]]*URL=' "$JOURNAL_UPLOAD_CONF" | tail -n1 || true)
    if [[ -n "$line" ]]; then
      line="${line#*=}"
      line="$(trim "$line")"
      echo "$line"
      return
    fi
  fi
  echo ""
}

has_systemctl() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

restart_service() {
  local service="$1" pretty="$2"
  local restarted=1

  if has_systemctl; then
    if systemctl restart "$service" >/dev/null 2>&1; then
      restarted=0
    fi
  fi

  if [[ $restarted -ne 0 ]] && command -v service >/dev/null 2>&1; then
    if service "$service" restart >/dev/null 2>&1; then
      restarted=0
    fi
  fi

  if [[ $restarted -eq 0 ]]; then
    msg_ok "$pretty restarted"
    SUMMARY+=("$pretty restart: success")
  else
    if ! has_systemctl && ! command -v service >/dev/null 2>&1; then
      msg_error "Cannot restart $pretty automatically (no service manager detected)"
      SUMMARY+=("$pretty restart: skipped (service manager unavailable)")
    else
      msg_error "Failed to restart $pretty; please restart manually"
      SUMMARY+=("$pretty restart: failed (manual intervention required)")
    fi
  fi
}

msg_info "Preparing journald persistent storage"
mkdir -p "$CONFIG_DIR"
if getent group systemd-journal >/dev/null 2>&1; then
  install -d -m 2755 -o root -g systemd-journal "$PERSIST_DIR"
else
  install -d -m 2755 -o root -g root "$PERSIST_DIR"
fi
msg_ok "Journal directory ensured at $PERSIST_DIR"

system_max_use_default="$(current_dropin_value "SystemMaxUse" "1G")"
system_keep_free_default="$(current_dropin_value "SystemKeepFree" "512M")"
runtime_max_use_default="$(current_dropin_value "RuntimeMaxUse" "200M")"
rate_limit_interval_default="$(current_dropin_value "RateLimitIntervalSec" "30s")"
rate_limit_burst_default="$(current_dropin_value "RateLimitBurst" "1000")"

system_max_use=$(ask_input "Persistent Journal Size" "Maximum disk usage for persistent logs (SystemMaxUse)" "$system_max_use_default") || system_max_use="$system_max_use_default"
system_max_use="${system_max_use:-$system_max_use_default}"

system_keep_free=$(ask_input "Reserve Disk Space" "Minimum free disk space to keep (SystemKeepFree)" "$system_keep_free_default") || system_keep_free="$system_keep_free_default"
system_keep_free="${system_keep_free:-$system_keep_free_default}"

runtime_max_use=$(ask_input "Runtime Journal Size" "Maximum size for runtime journal (RuntimeMaxUse)" "$runtime_max_use_default") || runtime_max_use="$runtime_max_use_default"
runtime_max_use="${runtime_max_use:-$runtime_max_use_default}"

rate_limit_interval=$(ask_input "Rate Limit Interval" "Interval for rate limiting new journal entries (RateLimitIntervalSec)" "$rate_limit_interval_default") || rate_limit_interval="$rate_limit_interval_default"
rate_limit_interval="${rate_limit_interval:-$rate_limit_interval_default}"

rate_limit_burst=$(ask_input "Rate Limit Burst" "Maximum entries accepted within interval (RateLimitBurst)" "$rate_limit_burst_default") || rate_limit_burst="$rate_limit_burst_default"
rate_limit_burst="${rate_limit_burst:-$rate_limit_burst_default}"

forward_to_syslog=""
remote_summary="Remote logging: disabled"
remote_choice=$(ask_menu "Remote Logging" 
  "Enable forwarding logs to a remote collector?" 
  "none" "No remote forwarding" 
  "rsyslog" "Forward using rsyslog" 
  "journal-remote" "Forward using systemd-journal-remote") || remote_choice="none"

rsyslog_conf_preexisting="no"
[[ -f "$RSYSLOG_CONF" ]] && rsyslog_conf_preexisting="yes"
journal_upload_conf_preexisting="no"
[[ -f "$JOURNAL_UPLOAD_CONF" ]] && journal_upload_conf_preexisting="yes"

case "$remote_choice" in
  rsyslog)
    current_target="$(current_rsyslog_target)"
    default_target="${current_target:-"@@log.example.com:6514"}"
    remote_target=$(ask_input "rsyslog target" "Enter remote rsyslog endpoint (use @@host:port for TCP).\nIf you omit the prefix, TCP @@ will be used." "$default_target") || remote_target="$default_target"
    remote_target="${remote_target:-$default_target}"
    remote_target="$(trim "$remote_target")"
    if [[ -z "$remote_target" ]]; then
      rm -f "$RSYSLOG_CONF"
      remote_summary="Remote logging: rsyslog skipped (no endpoint provided)"
    elif contains_inline_credentials "$remote_target"; then
      rm -f "$RSYSLOG_CONF"
      remote_summary="Remote logging: rsyslog skipped (inline credentials rejected)"
      msg_error "rsyslog endpoint must not contain inline credentials (user:pass@)"
    else
      if [[ "$remote_target" != @* ]]; then
        remote_target="@@${remote_target}"
      fi
      if [[ "$remote_target" != *:* ]]; then
        remote_target="${remote_target}:514"
      fi
      cat > "$RSYSLOG_CONF" <<RSY
# Managed by Raffo Setup logging helper
*.* ${remote_target}
RSY
      remote_summary="Remote logging: rsyslog -> ${remote_target}"
      forward_to_syslog="yes"
      services_to_restart+=("rsyslog")
      if [[ "$journal_upload_conf_preexisting" == "yes" ]]; then
        services_to_restart+=("systemd-journal-upload")
      fi
      rm -f "$JOURNAL_UPLOAD_CONF"
    fi
    ;;
  journal-remote)
    current_url="$(current_journal_url)"
    default_url="${current_url:-"https://logs.example.com:19532"}"
    upload_url=$(ask_input "systemd-journal-remote" "Enter systemd-journal-upload URL (e.g. https://collector:19532)" "$default_url") || upload_url="$default_url"
    upload_url="${upload_url:-$default_url}"
    upload_url="$(trim "$upload_url")"
    if [[ -z "$upload_url" ]]; then
      rm -f "$JOURNAL_UPLOAD_CONF"
      remote_summary="Remote logging: journal-upload skipped (no URL provided)"
    elif contains_inline_credentials "$upload_url"; then
      rm -f "$JOURNAL_UPLOAD_CONF"
      remote_summary="Remote logging: journal-upload skipped (inline credentials rejected)"
      msg_error "systemd-journal-upload URL must not contain inline credentials (user:pass@)"
    else
      mkdir -p "$JOURNAL_UPLOAD_DIR"
      cat > "$JOURNAL_UPLOAD_CONF" <<JUP
# Managed by Raffo Setup logging helper
[Upload]
URL=$upload_url
SplitMode=host
JUP
      remote_summary="Remote logging: systemd-journal-upload -> $upload_url"
      forward_to_syslog="no"
      services_to_restart+=("systemd-journal-upload")
      rm -f "$RSYSLOG_CONF"
      if [[ "$rsyslog_conf_preexisting" == "yes" ]]; then
        services_to_restart+=("rsyslog")
      fi
    fi
    ;;
  *)
    rsyslog_conf_was_present="no"
    journal_upload_conf_was_present="no"

    if [[ -f "$RSYSLOG_CONF" ]]; then
      rsyslog_conf_was_present="yes"
    fi

    if [[ -f "$JOURNAL_UPLOAD_CONF" ]]; then
      journal_upload_conf_was_present="yes"
    fi

    rm -f "$RSYSLOG_CONF" "$JOURNAL_UPLOAD_CONF"
    remote_summary="Remote logging: disabled"
    if [[ "$rsyslog_conf_was_present" == "yes" ]]; then
      services_to_restart+=("rsyslog")
    fi
    if [[ "$journal_upload_conf_was_present" == "yes" ]]; then
      services_to_restart+=("systemd-journal-upload")
    fi
    ;;
esac

{
  echo "# Managed by Raffo Setup logging helper"
  echo "[Journal]"
  echo "Storage=persistent"
  echo "SystemMaxUse=$system_max_use"
  echo "SystemKeepFree=$system_keep_free"
  echo "RuntimeMaxUse=$runtime_max_use"
  echo "RateLimitIntervalSec=$rate_limit_interval"
  echo "RateLimitBurst=$rate_limit_burst"
  if [[ -n "$forward_to_syslog" ]]; then
    echo "ForwardToSyslog=$forward_to_syslog"
  fi
} > "$DROPIN_FILE"
msg_ok "journald drop-in updated at $DROPIN_FILE"

SUMMARY+=("Journald storage: persistent (SystemMaxUse=$system_max_use, SystemKeepFree=$system_keep_free, RuntimeMaxUse=$runtime_max_use)")
SUMMARY+=("Rate limiting: Interval=$rate_limit_interval, Burst=$rate_limit_burst")
SUMMARY+=("$remote_summary")

if has_systemctl; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

declare -A seen_services=()
for svc in "${services_to_restart[@]}"; do
  [[ -n "${seen_services[$svc]:-}" ]] && continue
  seen_services[$svc]=1
  restart_service "$svc" "$svc"
done

echo
printf '%b\n' "${BL}Logging configuration summary${CL}"
for line in "${SUMMARY[@]}"; do
  echo -e " - $line"
done

