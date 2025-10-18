#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

escape_sed_regex() {
  printf '%s' "$1" | sed -e 's|[][\\.^$*+?{}()|/&]|\\&|g'
}

detect_active_firewall() {
  local svc
  for svc in ufw firewalld nftables iptables; do
    if systemctl is-active --quiet "$svc"; then
      echo "$svc"
      return 0
    fi
  done
  return 1
}

ensure_nftables_chains() {
  command -v nft >/dev/null 2>&1 || return 1
  nft list table inet filter >/dev/null 2>&1 || nft add table inet filter >/dev/null 2>&1 || true
  nft list chain inet filter input >/dev/null 2>&1 || \
    nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }' >/dev/null 2>&1 || true
}

ensure_emergency_ssh_rule() {
  local firewall
  firewall=$(detect_active_firewall) || return 0

  case "$firewall" in
    ufw)
      command -v ufw >/dev/null 2>&1 && \
        ufw allow 22/tcp comment 'Raffo emergency SSH' >/dev/null 2>&1 || true
      ;;
    firewalld)
      command -v firewall-cmd >/dev/null 2>&1 && \
        firewall-cmd --add-service=ssh >/dev/null 2>&1 || true
      ;;
    nftables)
      if ensure_nftables_chains; then
        nft add rule inet filter input tcp dport 22 counter accept >/dev/null 2>&1 || true
      fi
      ;;
    iptables)
      if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1 || \
          iptables -I INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1 || true
      fi
      ;;
  esac

  echo "Emergency SSH access ensured via $firewall"
}

preview_diff() {
  local title="$1" base="$2" new_file="$3"
  local diff_file
  diff_file=$(mktemp)
  if diff -u "$base" "$new_file" >"$diff_file"; then
    show_message "$title" "No differences detected."
  else
    show_textbox "$title" "$diff_file" 20 78 1
  fi
  rm -f "$diff_file"
}

duplicate_ip_check() {
  local iface="$1" new_ip="$2"
  local plain_ip
  plain_ip="${new_ip%%/*}"
  if [[ -z "$iface" || -z "$plain_ip" ]]; then
    return 0
  fi
  if ! command -v arping >/dev/null 2>&1; then
    echo "Skipping duplicate IP check (arping not installed)."
    return 0
  fi
  if arping -D -c 2 -w 3 -I "$iface" "$plain_ip" >/dev/null 2>&1; then
    return 0
  fi
  echo "Potential duplicate detected for $plain_ip on $iface."
  if ask_yesno "Duplicate IP detected" "ARP replies were received for $plain_ip on $iface. Proceed anyway?"; then
    return 0
  fi
  return 1
}

show_rollback_instructions() {
  local title="$1" message="$2"
  show_message "$title" "$message"
}

detect_runtime_ipv4() {
  local iface="$1"
  ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk 'NR==1 {print $4}'
}

detect_runtime_gateway() {
  local iface="$1"
  ip route show default 0.0.0.0/0 2>/dev/null | awk -v dev="$iface" '$5 == dev {print $3; exit}'
}

detect_system_dns() {
  if [[ -f /etc/resolv.conf ]]; then
    awk '/^nameserver/ {print $2}' /etc/resolv.conf | paste -sd' ' - 2>/dev/null || true
  fi
}

run_netplan_helper() {
  local mode="$1"
  shift
  python3 - "$mode" "$@" <<'PY'
import os
import sys
from collections import OrderedDict


def parse_scalar(text):
    text = text.strip()
    if not text:
        return ""
    lower = text.lower()
    if lower in {"true", "false"}:
        return lower == "true"
    if lower in {"null", "~"}:
        return None
    if (text.startswith("'") and text.endswith("'")) or (
        text.startswith('"') and text.endswith('"')
    ):
        text = text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        parts = []
        current = ""
        in_quote = None
        for ch in inner:
            if in_quote:
                if ch == in_quote:
                    in_quote = None
                elif ch == "\\":
                    current += ch
                    continue
                current += ch
                continue
            if ch in "'\"":
                in_quote = ch
                continue
            if ch == ',':
                parts.append(parse_scalar(current))
                current = ""
            else:
                current += ch
        if current:
            parts.append(parse_scalar(current))
        return parts
    return text


def determine_next_container_type(lines, start_idx, current_indent):
    for j in range(start_idx, len(lines)):
        raw = lines[j]
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        if indent <= current_indent:
            return 'dict'
        return 'list' if stripped.startswith('- ') else 'dict'
    return 'dict'


def parse_yaml(lines):
    root = OrderedDict()
    stack = [(-1, root)]
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        line = raw_line.split('#', 1)[0]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        indent = len(line) - len(line.lstrip(' '))
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if isinstance(parent, list):
            if stripped.startswith('- '):
                value_part = stripped[2:]
                value = parse_scalar(value_part)
                parent.append(value)
                i += 1
                continue
            raise ValueError(f'Invalid list item formatting: {raw_line}')
        if ':' not in stripped:
            raise ValueError(f'Invalid line: {raw_line}')
        key, value_part = stripped.split(':', 1)
        key = key.strip()
        value_part = value_part.strip()
        if value_part == '':
            container_type = determine_next_container_type(lines, i + 1, indent)
            container = [] if container_type == 'list' else OrderedDict()
            parent[key] = container
            stack.append((indent, container))
        else:
            value = parse_scalar(value_part)
            parent[key] = value
        i += 1
    return root


def format_scalar(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'null'
    text = str(value)
    if text == '':
        return "''"
    if any(ch in text for ch in ':#[]{}\n') or text.strip() != text or ' ' in text:
        return f'"{text}"'
    return text


def dump_yaml(value, indent=0, lines=None):
    if lines is None:
        lines = []
    pad = ' ' * indent
    if isinstance(value, OrderedDict):
        for key, val in value.items():
            if isinstance(val, (OrderedDict, list)):
                lines.append(f"{pad}{key}:")
                dump_yaml(val, indent + 2, lines)
            else:
                lines.append(f"{pad}{key}: {format_scalar(val)}")
    elif isinstance(value, dict):
        return dump_yaml(OrderedDict(value), indent, lines)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (OrderedDict, dict, list)):
                lines.append(f"{pad}-")
                dump_yaml(item, indent + 2, lines)
            else:
                lines.append(f"{pad}- {format_scalar(item)}")
    else:
        lines.append(f"{pad}{format_scalar(value)}")
    return lines


def parse_mode(path):
    with open(path, encoding='utf-8') as handle:
        data = parse_yaml(handle.read().splitlines())
    net = data.get('network')
    if not isinstance(net, dict):
        raise SystemExit('No network key found')
    section_name = None
    iface_name = None
    iface_data = None
    for candidate in ('ethernets', 'wifis', 'bonds', 'bridges', 'vlans'):
        section = net.get(candidate)
        if isinstance(section, dict) and section:
            for name, cfg in section.items():
                if isinstance(cfg, dict):
                    section_name = candidate
                    iface_name = name
                    iface_data = cfg
                    break
        if iface_data:
            break
    if not iface_data:
        raise SystemExit('No interface configuration found')
    address = ''
    addresses = iface_data.get('addresses')
    if isinstance(addresses, list) and addresses:
        first = addresses[0]
        if isinstance(first, str):
            address = first
    gateway = ''
    gateway_key = ''
    for key in ('gateway4', 'gateway6'):
        gw_candidate = iface_data.get(key)
        if isinstance(gw_candidate, str):
            gateway = gw_candidate
            gateway_key = key
            break
    dns = ''
    nameservers = iface_data.get('nameservers')
    if isinstance(nameservers, dict):
        dns_addrs = nameservers.get('addresses')
        if isinstance(dns_addrs, list):
            dns = ' '.join(str(x) for x in dns_addrs if isinstance(x, str))
    print(f'SECTION={section_name}')
    print(f'INTERFACE={iface_name}')
    print(f'GATEWAY_KEY={gateway_key}')
    print(f'ADDRESS={address}')
    print(f'GATEWAY={gateway}')
    print(f'DNS={dns}')


def update_mode(path, dest, section, interface):
    with open(path, encoding='utf-8') as handle:
        data = parse_yaml(handle.read().splitlines())
    net = data.get('network')
    if not isinstance(net, dict):
        net = OrderedDict()
        data['network'] = net
    section_data = net.get(section)
    if not isinstance(section_data, dict):
        raise SystemExit(f'Section {section} not found')
    iface_data = section_data.get(interface)
    if not isinstance(iface_data, dict):
        raise SystemExit(f'Interface {interface} not found')

    update_ip = os.environ.get('UPDATE_IP_FLAG') == '1'
    update_gw = os.environ.get('UPDATE_GW_FLAG') == '1'
    update_dns = os.environ.get('UPDATE_DNS_FLAG') == '1'
    new_ip = os.environ.get('NEW_IP_VALUE', '').strip()
    new_gw = os.environ.get('NEW_GW_VALUE', '').strip()
    new_dns = os.environ.get('NEW_DNS_VALUE', '').strip()
    gateway_key = os.environ.get('GATEWAY_KEY_VALUE', '').strip()

    if update_ip and new_ip:
        iface_data['addresses'] = [new_ip]
    if update_gw and new_gw:
        target_key = gateway_key if gateway_key else 'gateway4'
        iface_data[target_key] = new_gw
    if update_dns and new_dns:
        dns_list = [item for item in new_dns.split() if item]
        nameservers = iface_data.get('nameservers')
        if not isinstance(nameservers, dict):
            nameservers = OrderedDict()
        nameservers['addresses'] = dns_list
        iface_data['nameservers'] = nameservers

    with open(dest, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(dump_yaml(data)) + '\n')


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Mode not provided')
    mode = sys.argv[1]
    if mode == 'parse':
        if len(sys.argv) != 3:
            raise SystemExit('Usage: parse <file>')
        parse_mode(sys.argv[2])
    elif mode == 'update':
        if len(sys.argv) != 6:
            raise SystemExit('Usage: update <file> <dest> <section> <interface>')
        update_mode(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        raise SystemExit(f'Unknown mode {mode}')


if __name__ == '__main__':
    main()
PY
}

run_interfaces_helper() {
  local mode="$1"
  shift
  python3 - "$mode" "$@" <<'PY'
import re
import sys


IFACE_RE = re.compile(r'^\s*iface\s+(\S+)\s+inet\s+(\S+)\s*$')


def read_lines(path):
    with open(path, encoding='utf-8') as handle:
        return handle.read().splitlines()


def write_lines(path, lines):
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines) + '\n')


def find_block(lines, interface):
    start = end = None
    for idx, line in enumerate(lines):
        match = IFACE_RE.match(line)
        if match and match.group(1) == interface:
            start = idx
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                if IFACE_RE.match(lines[j]):
                    end = j
                    break
            return start, end
    raise SystemExit(f'Interface {interface} not found')


def parse_mode(path):
    lines = read_lines(path)
    for idx, line in enumerate(lines):
        match = IFACE_RE.match(line)
        if not match:
            continue
        name, method = match.group(1), match.group(2)
        if name == 'lo':
            continue
        address = ''
        gateway = ''
        dns = ''
        end = len(lines)
        for j in range(idx + 1, len(lines)):
            if IFACE_RE.match(lines[j]):
                end = j
                break
        for raw in lines[idx + 1:end]:
            stripped = raw.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.startswith('address '):
                address = stripped.split(None, 1)[1]
            elif stripped.startswith('gateway '):
                gateway = stripped.split(None, 1)[1]
            elif stripped.startswith('dns-nameservers '):
                dns = stripped.split(None, 1)[1]
        print(f'INTERFACE={name}')
        print(f'METHOD={method}')
        print(f'ADDRESS={address}')
        print(f'GATEWAY={gateway}')
        print(f'DNS={dns}')
        return
    raise SystemExit('No interface configuration found')


def update_mode(path, dest, interface, method, address, gateway, dns):
    lines = read_lines(path)
    start, end = find_block(lines, interface)
    block = lines[start:end]
    leading = block[0][: len(block[0]) - len(block[0].lstrip())]
    parts = block[0].strip().split()
    if len(parts) >= 4:
        parts[3] = method
    else:
        parts = ['iface', interface, 'inet', method]
    block[0] = f"{leading}{' '.join(parts)}"

    option_indent = None
    for raw in block[1:]:
        stripped = raw.strip()
        if stripped and not stripped.startswith('#'):
            option_indent = raw[: len(raw) - len(raw.lstrip())]
            break
    if option_indent is None:
        option_indent = '    '

    filtered = [block[0]]
    for raw in block[1:]:
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            filtered.append(raw)
            continue
        key = stripped.split(None, 1)[0]
        if key in {'address', 'netmask', 'gateway', 'dns-nameservers'}:
            continue
        filtered.append(raw)
    block = filtered

    if method == 'static':
        if address:
            block.append(f'{option_indent}address {address}')
        if gateway:
            block.append(f'{option_indent}gateway {gateway}')
        if dns:
            block.append(f'{option_indent}dns-nameservers {dns}')

    lines = lines[:start] + block + lines[end:]
    write_lines(dest, lines)


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Mode not provided')
    mode = sys.argv[1]
    if mode == 'parse':
        if len(sys.argv) != 3:
            raise SystemExit('Usage: parse <file>')
        parse_mode(sys.argv[2])
    elif mode == 'update':
        if len(sys.argv) != 9:
            raise SystemExit('Usage: update <file> <dest> <interface> <method> <address> <gateway> <dns>')
        update_mode(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
            sys.argv[5],
            sys.argv[6],
            sys.argv[7],
            sys.argv[8],
        )
    else:
        raise SystemExit(f'Unknown mode {mode}')


if __name__ == '__main__':
    main()
PY
}

shopt -s nullglob
NETPLAN_CANDIDATES=(/etc/netplan/*.yaml /etc/netplan/*.yml)
NETPLAN_FILES=()
for candidate in "${NETPLAN_CANDIDATES[@]}"; do
  [[ -f "$candidate" ]] && NETPLAN_FILES+=("$candidate")
done

if (( ${#NETPLAN_FILES[@]} > 0 )); then
  NETPLAN_FILE="${NETPLAN_FILES[0]}"
  echo "Netplan configuration file found: $NETPLAN_FILE"

  if ! mapfile -t NETPLAN_INFO < <(run_netplan_helper parse "$NETPLAN_FILE"); then
    echo "Failed to parse netplan configuration: $NETPLAN_FILE" >&2
    exit 1
  fi

  NETPLAN_SECTION=""
  NETPLAN_INTERFACE=""
  NETPLAN_GATEWAY_KEY=""
  CURRENT_IP=""
  CURRENT_GW=""
  CURRENT_DNS=""
  for entry in "${NETPLAN_INFO[@]}"; do
    key=${entry%%=*}
    value=${entry#*=}
    case "$key" in
      SECTION) NETPLAN_SECTION="$value" ;;
      INTERFACE) NETPLAN_INTERFACE="$value" ;;
      GATEWAY_KEY) NETPLAN_GATEWAY_KEY="$value" ;;
      ADDRESS) CURRENT_IP="$value" ;;
      GATEWAY) CURRENT_GW="$value" ;;
      DNS) CURRENT_DNS="$value" ;;
    esac
  done

  if [[ -z "$NETPLAN_SECTION" || -z "$NETPLAN_INTERFACE" ]]; then
    echo "Unable to locate a primary interface in $NETPLAN_FILE" >&2
    exit 1
  fi

  UPDATE_IP=0
  UPDATED_IP="$CURRENT_IP"
  if [[ -n "${CURRENT_IP:-}" ]]; then
    if ask_yesno "Change IP" "Current IP: $CURRENT_IP\n\nChange it?"; then
      NEW_IP=$(ask_input "New IP" "Enter IP (CIDR), e.g. 192.168.1.210/24" "$CURRENT_IP") || true
      if [[ -n "${NEW_IP:-}" ]]; then
        UPDATED_IP="$NEW_IP"
        UPDATE_IP=1
      fi
    fi
  fi

  UPDATE_GW=0
  UPDATED_GW="$CURRENT_GW"
  if [[ -n "${CURRENT_GW:-}" ]]; then
    if ask_yesno "Change Gateway" "Current gateway: $CURRENT_GW\n\nChange it?"; then
      NEW_GW=$(ask_input "New Gateway" "Enter new gateway" "$CURRENT_GW") || true
      if [[ -n "${NEW_GW:-}" ]]; then
        UPDATED_GW="$NEW_GW"
        UPDATE_GW=1
      fi
    fi
  fi

  UPDATE_DNS=0
  UPDATED_DNS="$CURRENT_DNS"
  if [[ -n "${CURRENT_DNS:-}" ]]; then
    if ask_yesno "Change DNS" "Current DNS: $CURRENT_DNS\n\nChange it?"; then
      NEW_DNS=$(ask_input "New DNS" "Space-separated DNS servers" "$CURRENT_DNS") || true
      if [[ -n "${NEW_DNS:-}" ]]; then
        UPDATED_DNS="$NEW_DNS"
        UPDATE_DNS=1
      fi
    fi
  fi

  if [[ "$UPDATE_IP" == 1 || "$UPDATE_GW" == 1 || "$UPDATE_DNS" == 1 ]]; then
    TMP_FILE=$(mktemp)
    if UPDATE_IP_FLAG="$UPDATE_IP" UPDATE_GW_FLAG="$UPDATE_GW" UPDATE_DNS_FLAG="$UPDATE_DNS" \
       NEW_IP_VALUE="$UPDATED_IP" NEW_GW_VALUE="$UPDATED_GW" NEW_DNS_VALUE="$UPDATED_DNS" \
       GATEWAY_KEY_VALUE="$NETPLAN_GATEWAY_KEY" run_netplan_helper update "$NETPLAN_FILE" "$TMP_FILE" "$NETPLAN_SECTION" "$NETPLAN_INTERFACE"; then
      preview_diff "Netplan changes" "$NETPLAN_FILE" "$TMP_FILE"

      if ! ACTION=$(ask_menu "Netplan apply" "Apply updated configuration?" \
        "apply-now" "Apply immediately" \
        "apply-after-reboot" "Save for next reboot" \
        "cancel" "Abort without changes"); then
        ACTION="cancel"
      fi
      case "$ACTION" in
        apply-now|apply-after-reboot)
          if [[ "$UPDATE_IP" == 1 ]]; then
            if ! duplicate_ip_check "$NETPLAN_INTERFACE" "$UPDATED_IP"; then
              rm -f "$TMP_FILE"
              exit 1
            fi
          fi
          BACKUP="$(raffo_backup "$NETPLAN_FILE" "netplan")"
          if [[ -n "$BACKUP" ]]; then
            echo "Backup created at $BACKUP"
          fi
          cp "$TMP_FILE" "$NETPLAN_FILE"
          if [[ "$ACTION" == "apply-now" ]]; then
            ensure_emergency_ssh_rule
            if ! netplan apply; then
              echo "netplan apply failed."
            fi
            show_rollback_instructions "Netplan rollback" "If connectivity fails, run:\n\ncp '$BACKUP' '$NETPLAN_FILE'\nnetplan apply"
          else
            show_rollback_instructions "Netplan staged" "Changes saved. They will take effect after reboot or 'netplan apply'.\n\nTo rollback before applying:\ncp '$BACKUP' '$NETPLAN_FILE'"
          fi
          ;;
        *)
          echo "Netplan update cancelled."
          ;;
      esac
      rm -f "$TMP_FILE"
    else
      rm -f "$TMP_FILE"
      echo "Failed to prepare netplan configuration: $NETPLAN_FILE" >&2
      exit 1
    fi
  else
    echo "No Netplan changes requested."
  fi

  exit 0
fi


IF_FILE="/etc/network/interfaces"
if [[ ! -f "$IF_FILE" ]]; then
  echo "Warning: no Netplan or /etc/network/interfaces configuration file found." >&2
  exit 0
fi

echo "Network configuration file found: $IF_FILE"

if ! mapfile -t IFACE_INFO < <(run_interfaces_helper parse "$IF_FILE"); then
  echo "Failed to parse $IF_FILE" >&2
  exit 1
fi

IFACE_NAME=""
IFACE_METHOD=""
CURRENT_IP=""
CURRENT_GW=""
CURRENT_DNS=""
for entry in "${IFACE_INFO[@]}"; do
  key=${entry%%=*}
  value=${entry#*=}
  case "$key" in
    INTERFACE) IFACE_NAME="$value" ;;
    METHOD) IFACE_METHOD="$value" ;;
    ADDRESS) CURRENT_IP="$value" ;;
    GATEWAY) CURRENT_GW="$value" ;;
    DNS) CURRENT_DNS="$value" ;;
  esac
done

if [[ -z "$IFACE_NAME" ]]; then
  echo "Unable to identify primary interface from $IF_FILE" >&2
  exit 1
fi

DETECTED_IP=$(detect_runtime_ipv4 "$IFACE_NAME")
DETECTED_GW=$(detect_runtime_gateway "$IFACE_NAME")
DETECTED_DNS=$(detect_system_dns)

TARGET_METHOD="$IFACE_METHOD"
FINAL_IP="$CURRENT_IP"
FINAL_GW="$CURRENT_GW"
FINAL_DNS="$CURRENT_DNS"

if [[ "$IFACE_METHOD" == "dhcp" ]]; then
  DETECT_MSG="Detected IPv4: ${DETECTED_IP:-Unavailable}"
  if [[ -n "$DETECTED_GW" ]]; then
    DETECT_MSG+=$'\n'"Detected gateway: $DETECTED_GW"
  fi
  if [[ -n "$DETECTED_DNS" ]]; then
    DETECT_MSG+=$'\n'"Detected DNS: $DETECTED_DNS"
  fi
  if ! ACTION=$(ask_menu "Network configuration" "Current method: DHCP\n\n$DETECT_MSG\n\nChoose an action." "keep-dhcp" "Keep DHCP (no changes)" "switch-static" "Switch to a static configuration" "cancel" "Cancel"); then
    ACTION="cancel"
  fi
  case "$ACTION" in
    keep-dhcp)
      echo "No interface changes requested."
      exit 0
      ;;
    switch-static)
      TARGET_METHOD="static"
      ;;
    *)
      echo "Interfaces update cancelled."
      exit 0
      ;;
  esac
elif [[ "$IFACE_METHOD" == "static" ]]; then
  if ! ACTION=$(ask_menu "Network configuration" "Current method: static\n\nChoose an action." "edit-static" "Edit static settings" "switch-dhcp" "Switch to DHCP" "cancel" "Cancel"); then
    ACTION="cancel"
  fi
  case "$ACTION" in
    edit-static)
      TARGET_METHOD="static"
      ;;
    switch-dhcp)
      TARGET_METHOD="dhcp"
      ;;
    *)
      echo "Interfaces update cancelled."
      exit 0
      ;;
  esac
else
  if ! ACTION=$(ask_menu "Network configuration" "Current method: $IFACE_METHOD\n\nChoose desired configuration." "switch-static" "Switch to a static configuration" "switch-dhcp" "Switch to DHCP" "cancel" "Cancel"); then
    ACTION="cancel"
  fi
  case "$ACTION" in
    switch-static)
      TARGET_METHOD="static"
      ;;
    switch-dhcp)
      TARGET_METHOD="dhcp"
      ;;
    *)
      echo "Interfaces update cancelled."
      exit 0
      ;;
  esac
fi

if [[ "$TARGET_METHOD" == "static" && "$IFACE_METHOD" == "dhcp" ]]; then
  [[ -z "$FINAL_IP" && -n "$DETECTED_IP" ]] && FINAL_IP="$DETECTED_IP"
  [[ -z "$FINAL_GW" && -n "$DETECTED_GW" ]] && FINAL_GW="$DETECTED_GW"
  [[ -z "$FINAL_DNS" && -n "$DETECTED_DNS" ]] && FINAL_DNS="$DETECTED_DNS"
fi

if [[ "$TARGET_METHOD" == "static" ]]; then
  if [[ -n "$FINAL_IP" ]]; then
    if ask_yesno "Change IP" "Current IP: $FINAL_IP\n\nChange it?"; then
      NEW_IP=$(ask_input "New IP" "Enter IP (CIDR), e.g. 192.168.1.210/24" "$FINAL_IP") || true
      if [[ -n "${NEW_IP:-}" ]]; then
        FINAL_IP="$NEW_IP"
      fi
    fi
  else
    while :; do
      NEW_IP=$(ask_input "New IP" "Enter IP (CIDR), e.g. 192.168.1.210/24" "${DETECTED_IP:-}") || true
      if [[ -n "${NEW_IP:-}" ]]; then
        FINAL_IP="$NEW_IP"
        break
      fi
      if ! ask_yesno "Missing IP" "A static configuration requires an IP address. Try again?"; then
        echo "Interfaces update cancelled."
        exit 0
      fi
    done
  fi

  if [[ -n "$FINAL_GW" ]]; then
    if ask_yesno "Change Gateway" "Current gateway: $FINAL_GW\n\nChange it?"; then
      NEW_GW=$(ask_input "New Gateway" "Enter new gateway" "$FINAL_GW") || true
      if [[ -n "${NEW_GW:-}" ]]; then
        FINAL_GW="$NEW_GW"
      fi
    fi
  else
    if ask_yesno "Configure Gateway" "No gateway configured. Add one?"; then
      NEW_GW=$(ask_input "Gateway" "Enter gateway address" "${DETECTED_GW:-}") || true
      if [[ -n "${NEW_GW:-}" ]]; then
        FINAL_GW="$NEW_GW"
      fi
    fi
  fi

  if [[ -n "$FINAL_DNS" ]]; then
    if ask_yesno "Change DNS" "Current DNS: $FINAL_DNS\n\nChange it?"; then
      NEW_DNS=$(ask_input "New DNS" "Space-separated DNS servers" "$FINAL_DNS") || true
      if [[ -n "${NEW_DNS:-}" ]]; then
        FINAL_DNS="$NEW_DNS"
      fi
    fi
  else
    if ask_yesno "Configure DNS" "No DNS servers configured. Add them?"; then
      NEW_DNS=$(ask_input "DNS Servers" "Space-separated DNS servers" "${DETECTED_DNS:-}") || true
      if [[ -n "${NEW_DNS:-}" ]]; then
        FINAL_DNS="$NEW_DNS"
      fi
    fi
  fi

  if [[ -z "$FINAL_IP" ]]; then
    show_message "Invalid configuration" "Static configuration requires an IP address. Aborting."
    exit 1
  fi
fi

TMP_FILE=$(mktemp)
if ! run_interfaces_helper update "$IF_FILE" "$TMP_FILE" "$IFACE_NAME" "$TARGET_METHOD" "${FINAL_IP:-}" "${FINAL_GW:-}" "${FINAL_DNS:-}"; then
  rm -f "$TMP_FILE"
  echo "Failed to render interface configuration." >&2
  exit 1
fi

preview_diff "Interfaces changes" "$IF_FILE" "$TMP_FILE"

if ! ACTION=$(ask_menu "Apply interfaces" "Apply updated configuration?" "apply-now" "Apply immediately" "apply-after-reboot" "Save for next reboot" "cancel" "Abort without changes"); then
  ACTION="cancel"
fi

case "$ACTION" in
  apply-now|apply-after-reboot)
    if [[ "$TARGET_METHOD" == "static" ]]; then
      if ! duplicate_ip_check "$IFACE_NAME" "$FINAL_IP"; then
        rm -f "$TMP_FILE"
        exit 1
      fi
    fi
    BACKUP="$(raffo_backup "$IF_FILE" "interfaces")"
    if [[ -n "$BACKUP" ]]; then
      echo "Backup created at $BACKUP"
    fi
    cp "$TMP_FILE" "$IF_FILE"
    if [[ "$ACTION" == "apply-now" ]]; then
      ensure_emergency_ssh_rule
      if systemctl is-active --quiet networking; then
        systemctl reload networking >/dev/null 2>&1 || systemctl restart networking >/dev/null 2>&1 || true
      fi
      show_rollback_instructions "Interfaces rollback" "If connectivity fails, run:\n\ncp '$BACKUP' '$IF_FILE'\nifdown '$IFACE_NAME' && ifup '$IFACE_NAME'"
    else
      show_rollback_instructions "Interfaces staged" "Changes saved. They will take effect after reboot or network restart.\n\nTo rollback before applying:\ncp '$BACKUP' '$IF_FILE'"
    fi
    ;;
  *)
    echo "Interfaces update cancelled."
    ;;
esac

rm -f "$TMP_FILE"

exit 0
