#!/bin/bash
# Interactive helper that consumes inspectnetworksjson.sh output and lets the
# operator review or edit the discovered network connection JSON payloads.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./raffolib.sh
source "$SCRIPT_DIR/raffolib.sh"

INSPECT_SCRIPT="$SCRIPT_DIR/inspectnetworksjson.sh"

# Ensure the array exists even if the inspector fails to emit it, to avoid nounset errors.
declare -a connections=()

temp_files=()
cleanup() {
  local file
  for file in "${temp_files[@]:-}"; do
    [[ -n "$file" && -f "$file" ]] && rm -f "$file"
  done
}
trap cleanup EXIT

ensure_whiptail() {
  if ! command -v whiptail >/dev/null 2>&1; then
    echo "whiptail is required for setupnetworkjson.sh" >&2
    exit 1
  fi
}

load_network_payload() {
  local data_file info_file
  data_file="$(mktemp)"
  info_file="$(mktemp)"
  temp_files+=("$data_file" "$info_file")

  if ! bash "$INSPECT_SCRIPT" --dump-shell >"$data_file" 2>"$info_file"; then
    local message
    message=$(<"$info_file")
    if [[ -z "$message" ]]; then
      message="Failed to load network data from $INSPECT_SCRIPT"
    fi
    show_message "Network inspection failed" "$message"
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$data_file"

  # If the sourced data didn't define the array for any reason, keep it as an empty array.
  declare -p connections >/dev/null 2>&1 || declare -a connections=()
}

connection_summary() {
  local json="$1"
  python - "$json" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
name = payload.get("name") or "(unnamed)"
state = payload.get("state") or "N/A"
mtu = payload.get("mtu")
mac = payload.get("mac") or "N/A"
default_v4 = "Yes" if payload.get("default_ipv4") else "No"
default_v6 = "Yes" if payload.get("default_ipv6") else "No"
addr4 = payload.get("ipv4_addresses") or []
addr6 = payload.get("ipv6_addresses") or []
routes4 = payload.get("ipv4_routes") or []
routes6 = payload.get("ipv6_routes") or []
lines = [
    f"Interface: {name}",
    f"  State: {state}",
    f"  MTU: {mtu if mtu is not None else 'N/A'}",
    f"  MAC: {mac}",
    f"  Default IPv4: {default_v4}",
    f"  Default IPv6: {default_v6}",
    "  IPv4 addresses: " + (", ".join(addr4) if addr4 else "(none)"),
    "  IPv6 addresses: " + (", ".join(addr6) if addr6 else "(none)"),
    "  IPv4 routes: " + (", ".join(routes4) if routes4 else "(none)"),
    "  IPv6 routes: " + (", ".join(routes6) if routes6 else "(none)"),
]
print("\n".join(lines))
PY
}

prompt_edit_field() {
  local title="$1"
  local message="$2"
  local default_value="$3"
  local input
  if input=$(ask_input "$title" "$message" "$default_value"); then
    printf '%s' "$input"
    return 0
  fi
  return 1
}

prompt_boolean_field() {
  local title="$1"
  local current="$2"
  if ask_yesno "$title" "$current"; then
    printf 'true'
    return 0
  fi

  local status=$?
  if (( status == 1 )); then
    printf 'false'
    return 0
  fi

  return 1
}

edit_connection() {
  local index="$1"
  local json="${connections[$index]}"
  local key encoded decoded
  declare -A fields=()
  declare -A original=()

  while IFS='=' read -r key encoded; do
    decoded="$(printf '%s' "$encoded" | base64 --decode)"
    fields["$key"]="$decoded"
    original["$key"]="$decoded"
  done < <(python - "$json" <<'PY'
import json, sys, base64
payload = json.loads(sys.argv[1])
keys = [
    "name",
    "state",
    "mtu",
    "mac",
    "ipv4_addresses",
    "ipv6_addresses",
    "ipv4_routes",
    "ipv6_routes",
    "default_ipv4",
    "default_ipv6",
]
for item in keys:
    value = payload.get(item)
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value)
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif value is None:
        text = ""
    else:
        text = str(value)
    encoded = base64.b64encode(text.encode()).decode()
    print(f"{item}={encoded}")
PY
)

  local new_value

  if new_value=$(prompt_edit_field "Connection name" $'Update the interface name.\nLeave blank to clear.' "${fields[name]}"); then
    fields[name]="$new_value"
  fi
  if new_value=$(prompt_edit_field "Interface state" $'Update the recorded state (e.g. UP, DOWN).\nLeave blank to clear.' "${fields[state]}"); then
    fields[state]="$new_value"
  fi
  if new_value=$(prompt_edit_field "Interface MTU" $'Update the MTU value (numeric).\nLeave blank to clear.' "${fields[mtu]}"); then
    fields[mtu]="$new_value"
  fi
  if new_value=$(prompt_edit_field "MAC address" $'Update the MAC address.\nLeave blank to clear.' "${fields[mac]}"); then
    fields[mac]="$new_value"
  fi
  if new_value=$(prompt_edit_field "IPv4 addresses" $'Provide comma-separated IPv4 addresses.\nLeave blank to clear.' "${fields[ipv4_addresses]}"); then
    fields[ipv4_addresses]="$new_value"
  fi
  if new_value=$(prompt_edit_field "IPv6 addresses" $'Provide comma-separated IPv6 addresses.\nLeave blank to clear.' "${fields[ipv6_addresses]}"); then
    fields[ipv6_addresses]="$new_value"
  fi
  if new_value=$(prompt_edit_field "IPv4 routes" $'Provide comma-separated IPv4 routes.\nLeave blank to clear.' "${fields[ipv4_routes]}"); then
    fields[ipv4_routes]="$new_value"
  fi
  if new_value=$(prompt_edit_field "IPv6 routes" $'Provide comma-separated IPv6 routes.\nLeave blank to clear.' "${fields[ipv6_routes]}"); then
    fields[ipv6_routes]="$new_value"
  fi

  local bool_prompt
  bool_prompt=$(printf 'Current value: %s\nChoose Yes for "true" or No for "false".' "${fields[default_ipv4]:-false}")
  if new_value=$(prompt_boolean_field "Default IPv4" "$bool_prompt"); then
    fields[default_ipv4]="$new_value"
  fi
  bool_prompt=$(printf 'Current value: %s\nChoose Yes for "true" or No for "false".' "${fields[default_ipv6]:-false}")
  if new_value=$(prompt_boolean_field "Default IPv6" "$bool_prompt"); then
    fields[default_ipv6]="$new_value"
  fi

  local updated_json
  updated_json=$(python - <<'PY' \
    "${fields[name]}" \
    "${fields[state]}" \
    "${fields[mtu]}" \
    "${fields[mac]}" \
    "${fields[ipv4_addresses]}" \
    "${fields[ipv6_addresses]}" \
    "${fields[ipv4_routes]}" \
    "${fields[ipv6_routes]}" \
    "${fields[default_ipv4]}" \
    "${fields[default_ipv6]}" \
    "${original[mtu]}"
import json, sys
(
    name,
    state,
    mtu,
    mac,
    ipv4_addrs,
    ipv6_addrs,
    ipv4_routes,
    ipv6_routes,
    default_ipv4,
    default_ipv6,
    original_mtu,
) = sys.argv[1:]

def parse_optional(value):
    text = value.strip()
    return text if text else None

def parse_list(value):
    text = value.strip()
    if not text:
        return []
    return [item.strip() for item in text.split(',') if item.strip()]

def parse_bool(value):
    text = value.strip().lower()
    if text in ('true', '1', 'yes', 'y'):
        return True
    if text in ('false', '0', 'no', 'n'):
        return False
    return False

def parse_mtu(value, original):
    text = value.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        original = original.strip()
        if not original:
            return None
        try:
            return int(original)
        except ValueError:
            return None

payload = {
    'name': parse_optional(name),
    'state': parse_optional(state),
    'mtu': parse_mtu(mtu, original_mtu),
    'mac': parse_optional(mac),
    'ipv4_addresses': parse_list(ipv4_addrs),
    'ipv6_addresses': parse_list(ipv6_addrs),
    'ipv4_routes': parse_list(ipv4_routes),
    'ipv6_routes': parse_list(ipv6_routes),
    'default_ipv4': parse_bool(default_ipv4),
    'default_ipv6': parse_bool(default_ipv6),
}
print(json.dumps(payload))
PY
  )

  connections[index]="$updated_json"
}

emit_connections_json() {
  python - "$@" <<'PY'
import json, sys
payload = [json.loads(item) for item in sys.argv[1:]]
json.dump(payload, sys.stdout)
PY
}

main() {
  ensure_whiptail
  load_network_payload

  if [[ ${#connections[@]} -eq 0 ]]; then
    show_message "Network connections" "No network connections were discovered."
    printf '[]\n'
    return
  fi

  if ! ask_yesno "Network connections" $'Do you want to review or edit the detected connections?'; then
    local status=$?
    if (( status == 0 )); then
      : # never happens
    elif (( status == 1 )); then
      show_message "Network connections" "Editing skipped."
    fi
    printf '%s\n' "$(emit_connections_json "${connections[@]}")"
    return
  fi

  local idx summary title prompt
  for idx in "${!connections[@]}"; do
    summary="$(connection_summary "${connections[$idx]}")"
    title="Connection $(( idx + 1 ))/${#connections[@]}"
    prompt="$summary$'\n\nEdit this connection?'"
    if ask_yesno "$title" "$prompt"; then
      edit_connection "$idx"
    fi
  done

  local final_json
  final_json="$(emit_connections_json "${connections[@]}")"

  local final_file
  final_file="$(mktemp)"
  temp_files+=("$final_file")
  printf '%s\n' "$final_json" >"$final_file"
  show_textbox "Updated connections" "$final_file" 20 90 1 || true

  printf '%s\n' "$final_json"
}

main "$@"
