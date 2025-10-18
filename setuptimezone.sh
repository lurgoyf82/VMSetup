#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

if ! command -v timedatectl >/dev/null; then
  msg_error "timedatectl not available"
  exit 1
fi

current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
msg_info "Current timezone: $current_tz"
msg_ok "Loaded timezone information"

mapfile -t regions < <(timedatectl list-timezones | cut -d'/' -f1 | sort -u)
regions+=("UTC")

region_menu_args=()
for region in "${regions[@]}"; do
  region_menu_args+=("$region" " ")
done

selected_region=$(ask_menu "Timezone Region" \
  "Select the geographic region" \
  "${region_menu_args[@]}") || {
    msg_ok "Timezone configuration skipped"
    exit 0
  }

if [[ "$selected_region" == "UTC" ]]; then
  new_timezone="UTC"
else
  mapfile -t zone_list < <(timedatectl list-timezones | grep "^${selected_region}/")
  zone_menu_args=()
  for zone in "${zone_list[@]}"; do
    zone_menu_args+=("$zone" " ")
  done
  new_timezone=$(ask_menu "Timezone City" \
    "Select the closest city" \
    "${zone_menu_args[@]}") || {
      msg_ok "Timezone configuration skipped"
      exit 0
    }
fi

if [[ "$new_timezone" != "$current_tz" ]]; then
  msg_info "Setting timezone to $new_timezone"
  timedatectl set-timezone "$new_timezone"
  msg_ok "Timezone updated to $new_timezone"
else
  msg_ok "Timezone already set to $new_timezone"
fi

