#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if ! command -v timedatectl >/dev/null 2>&1; then
  msg_error "timedatectl not available"
  exit 1
fi

log_file="/var/log/raffo-timesync.log"
mkdir -p "$(dirname "$log_file")"

current_timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
msg_info "Current timezone: ${current_timezone}"

mapfile -t available_timezones < <(timedatectl list-timezones)
if [[ ${#available_timezones[@]} -eq 0 ]]; then
  msg_error "No timezones returned by timedatectl"
  exit 1
fi

menu_args=()
for tz in "${available_timezones[@]}"; do
  menu_args+=("$tz" " ")
done

selected_timezone=$(ask_menu "System Timezone" "Select the timezone for this system" --size 20 70 18 "${menu_args[@]}") || {
    msg_ok "Time synchronization configuration skipped"
    exit 0
  }

if [[ "$selected_timezone" != "$current_timezone" ]]; then
  msg_info "Setting timezone to ${selected_timezone}"
  timedatectl set-timezone "$selected_timezone"
  msg_ok "Timezone updated to ${selected_timezone}"
else
  msg_ok "Timezone already set to ${selected_timezone}"
fi

SYNC_CHOICES=(
  "systemd-timesyncd" "Use built-in systemd time synchronization"
  "chrony" "Use chrony NTP service"
  "skip" "Skip NTP service configuration"
)

selected_service=$(ask_menu "Time Synchronization" \
  "Select the preferred NTP service" \
  "${SYNC_CHOICES[@]}") || selected_service="skip"

case "$selected_service" in
  systemd-timesyncd)
    msg_info "Enabling systemd-timesyncd"
    if systemctl list-unit-files chrony.service >/dev/null 2>&1; then
      systemctl disable --now chrony.service >/dev/null 2>&1 || true
    fi
    systemctl unmask systemd-timesyncd.service >/dev/null 2>&1 || true
    systemctl enable --now systemd-timesyncd.service >/dev/null
    active_service="systemd-timesyncd"
    ;;
  chrony)
    msg_info "Configuring chrony"
    export DEBIAN_FRONTEND=noninteractive
    if ! dpkg -s chrony >/dev/null 2>&1; then
      apt-get update -y >/dev/null
      apt-get install -y chrony >/dev/null
    fi
    systemctl disable --now systemd-timesyncd.service >/dev/null 2>&1 || true
    systemctl enable --now chrony.service >/dev/null
    active_service="chrony"
    ;;
  *)
    msg_ok "Time synchronization service left unchanged"
    active_service=""
    ;;
esac

sleep 2

sync_status=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "no")
system_sync=$(timedatectl show --property=SystemClockSynchronized --value 2>/dev/null || echo "no")
offset_info="unknown"
status_details=""

status_details=$(timedatectl timesync-status 2>/dev/null || true)
if [[ -n "$status_details" ]]; then
  offset_info=$(grep -m1 'Offset:' <<<"$status_details" | awk -F':' '{gsub(/^ +| +$/,"",$2); print $2}')
fi

if [[ -z "$status_details" || -z "$offset_info" || "$offset_info" == "" ]]; then
  if command -v chronyc >/dev/null 2>&1; then
    status_details=$(chronyc tracking 2>/dev/null || true)
    if [[ -n "$status_details" ]]; then
      offset_info=$(grep -m1 'Last offset' <<<"$status_details" | awk -F':' '{gsub(/^ +| +$/,"",$2); print $2}')
    fi
  fi
fi

if [[ -z "$offset_info" || "$offset_info" == "" ]]; then
  offset_info="unknown"
fi

{
  echo "[$(date --iso-8601=seconds)] Timezone=${selected_timezone} Service=${active_service:-unchanged} NTPSynchronized=${sync_status} SystemClockSynchronized=${system_sync} Offset=${offset_info}"
  if [[ -n "$status_details" ]]; then
    echo "$status_details"
  fi
  echo
} >>"$log_file"

if [[ "$sync_status" == "yes" || "$system_sync" == "yes" ]]; then
  msg_ok "Time synchronization verified (offset: ${offset_info})"
else
  msg_error "System clock is not synchronized. See ${log_file} for details."
fi
