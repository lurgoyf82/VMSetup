#!/usr/bin/env bash
set -euo pipefail

# bring in whiptail helpers and colors
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

echo "=== Firewall configuration ==="

# --- state/summary helpers (unchanged) ---
RAFFO_STATE_DIR=${RAFFO_STATE_DIR:-/var/lib/raffosetup}
RAFFO_BACKUP_DIR=${RAFFO_BACKUP_DIR:-$RAFFO_STATE_DIR/backups}
SETUP_SUMMARY_FILE=${SETUP_SUMMARY_FILE:-$RAFFO_STATE_DIR/setup-summary.txt}
mkdir -p "$RAFFO_STATE_DIR" "$RAFFO_BACKUP_DIR"

raffo_timestamp() { date +%Y%m%d%H%M%S; }
log_summary() { local line="$1"; mkdir -p "$(dirname "$SETUP_SUMMARY_FILE")"; echo "$line" >>"$SETUP_SUMMARY_FILE"; }
trim() { local var="$1"; var="${var#${var%%[![:space:]]*}}"; var="${var%${var##*[![:space:]]}}"; echo "$var"; }

SSH_PORT_STATE_FILE="/var/lib/raffosetup/ssh_port"
SSH_PORT=""
[[ -f "$SSH_PORT_STATE_FILE" ]] && SSH_PORT="$(tr -d '\n\r\t ' <"$SSH_PORT_STATE_FILE")"

# --- helper functions (unchanged logic) ---
parse_port_spec() { local spec="$1" proto="tcp" port="$spec"; [[ "$spec" == */* ]] && { proto="${spec##*/}"; port="${spec%/*}"; }; echo "$port $proto"; }
ensure_nftables_chains() {
  nft list table inet filter >/dev/null 2>&1 || nft add table inet filter
  nft list chain  inet filter input   >/dev/null 2>&1 || nft add chain inet filter input   '{ type filter hook input priority 0; policy accept; }'
  nft list chain  inet filter forward >/dev/null 2>&1 || nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
  nft list chain  inet filter output  >/dev/null 2>&1 || nft add chain inet filter output  '{ type filter hook output priority 0; policy accept; }'
}
snapshot_firewall() { case "$1" in
  ufw)       ufw status numbered 2>/dev/null || true ;;
  firewalld) firewall-cmd --list-all-zones 2>/dev/null || true ;;
  nftables)  nft list ruleset 2>/dev/null || true ;;
  iptables)  { iptables-save 2>/dev/null; ip6tables-save 2>/dev/null; } || true ;;
esac; }
backup_firewall_rules() { local backend="$1" data="$2"; [[ -z "$data" ]] && return 0; local path="$RAFFO_BACKUP_DIR/firewall-${backend}-$(raffo_timestamp).rules"; printf '%s\n' "$data" >"$path"; chmod 600 "$path"; echo "$path"; }
ensure_firewalld_reload=0

declare -A SERVICE_GROUPS=(
  [ssh]="22/tcp" [http]="80/tcp" [https]="443/tcp" [web]="80/tcp 443/tcp" [http-alt]="8080/tcp"
  [dns]="53/tcp 53/udp" [ntp]="123/udp" [smtp]="25/tcp" [pop3]="110/tcp" [imap]="143/tcp"
)
declare -a ALLOWED_RULES DENIED_RULES

list_service_groups() {
  local out=""; for name in "${!SERVICE_GROUPS[@]}"; do out+="$name (${SERVICE_GROUPS[$name]})\n"; done
  printf '%b' "$(echo -e "$out" | sort)"
}

ensure_ssh_access() {
  case "$ACTIVE_FW" in
    ufw)       ufw allow "22/tcp" >/dev/null 2>&1 || ufw allow ssh ;;
    firewalld) firewall-cmd --add-service=ssh --permanent >/dev/null 2>&1 && ensure_firewalld_reload=1; firewall-cmd --add-service=ssh >/dev/null 2>&1 || true ;;
    nftables)  ensure_nftables_chains; nft list chain inet filter input 2>/dev/null | grep -F "tcp dport 22" >/dev/null || nft add rule inet filter input tcp dport 22 counter accept ;;
    iptables)  iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 22 -j ACCEPT
               command -v ip6tables >/dev/null 2>&1 && { ip6tables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 22 -j ACCEPT; } ;;
  esac
}

firewalld_rich_rule_family() { local source="$1"; [[ -z "$source" ]] && { echo ipv4; return; }; [[ "$source" == *:* ]] && echo ipv6 || echo ipv4; }

apply_rule() {
  local action="$1" port_number="$2" protocol="$3" source="$4" family proto_flag="$protocol"
  case "$ACTIVE_FW" in
    ufw)
      local ufw_action; [[ "$action" == "allow" ]] && ufw_action="allow" || ufw_action="deny"
      [[ -n "$source" ]] && ufw "$ufw_action" from "$source" to any port "$port_number" proto "$proto_flag" || ufw "$ufw_action" "$port_number/$proto_flag"
      ;;
    firewalld)
      ensure_firewalld_reload=1
      if [[ "$action" == "allow" ]]; then
        if [[ "$port_number" == "22" && "$protocol" == "tcp" && -z "$source" ]]; then
          firewall-cmd --add-service=ssh --permanent >/dev/null 2>&1; firewall-cmd --add-service=ssh >/dev/null 2>&1 || true
        elif [[ -n "$source" ]]; then
          family=$(firewalld_rich_rule_family "$source")
          local r="rule family=${family} source address=${source} port protocol=${protocol} port=${port_number} accept"
          firewall-cmd --add-rich-rule="$r" --permanent; firewall-cmd --add-rich-rule="$r" >/dev/null 2>&1 || true
        else
          firewall-cmd --add-port="${port_number}/${protocol}" --permanent; firewall-cmd --add-port="${port_number}/${protocol}" >/dev/null 2>&1 || true
        fi
      else
        family=$(firewalld_rich_rule_family "$source")
        if [[ -n "$source" ]]; then
          local r="rule family=${family} source address=${source} port protocol=${protocol} port=${port_number} drop"
          firewall-cmd --add-rich-rule="$r" --permanent; firewall-cmd --add-rich-rule="$r" >/dev/null 2>&1 || true
        else
          local r4="rule family=ipv4 port protocol=${protocol} port=${port_number} drop"
          local r6="rule family=ipv6 port protocol=${protocol} port=${port_number} drop"
          firewall-cmd --add-rich-rule="$r4" --permanent; firewall-cmd --add-rich-rule="$r6" --permanent
          firewall-cmd --add-rich-rule="$r4" >/dev/null 2>&1 || true; firewall-cmd --add-rich-rule="$r6" >/dev/null 2>&1 || true
        fi
      fi
      ;;
    nftables)
      ensure_nftables_chains
      local source_clause=""; [[ -n "$source" ]] && { [[ "$source" == *:* ]] && source_clause="ip6 saddr ${source}" || source_clause="ip saddr ${source}"; }
      [[ "$action" == "allow" ]] && nft add rule inet filter input ${source_clause} ${protocol} dport ${port_number} counter accept \
                                  || nft add rule inet filter input ${source_clause} ${protocol} dport ${port_number} counter drop
      ;;
    iptables)
      local ip6=0; local -a args=("-p" "$protocol" "--dport" "$port_number"); [[ -n "$source" ]] && { args+=("-s" "$source"); [[ "$source" == *:* ]] && ip6=1; }
      if [[ "$action" == "allow" ]]; then
        if [[ $ip6 -eq 1 ]]; then command -v ip6tables >/dev/null 2>&1 && { ip6tables -C INPUT "${args[@]}" -j ACCEPT 2>/dev/null || ip6tables -I INPUT "${args[@]}" -j ACCEPT; }
        else iptables -C INPUT "${args[@]}" -j ACCEPT 2>/dev/null || iptables -I INPUT "${args[@]}" -j ACCEPT; fi
      else
        if [[ $ip6 -eq 1 ]]; then command -v ip6tables >/dev/null 2>&1 && { ip6tables -C INPUT "${args[@]}" -j DROP 2>/dev/null || ip6tables -I INPUT "${args[@]}" -j DROP; }
        else iptables -C INPUT "${args[@]}" -j DROP 2>/dev/null || iptables -I INPUT "${args[@]}" -j DROP; fi
      fi
      ;;
  esac
}

# --- detect/enable backend (whiptail) ---
ACTIVE_FW=$(for svc in ufw firewalld nftables iptables; do systemctl is-active --quiet "$svc" && echo "$svc"; done | head -n1)
if [[ -z "${ACTIVE_FW:-}" ]]; then
  CHOICE="$(ask_menu "Firewall backend" "No active firewall detected.\nChoose one to enable:" \
            "ufw" "Uncomplicated Firewall" \
            "firewalld" "Firewalld (zones/services)" \
            "nftables" "nftables (modern netfilter)" \
            "iptables" "iptables (legacy)" \
            "none" "Do nothing")" || CHOICE="none"
  case "$CHOICE" in
    ufw|firewalld|nftables|iptables) systemctl enable --now "$CHOICE" 2>/dev/null || true; ACTIVE_FW="$CHOICE" ;;
    *) msg_info "No firewall selected"; echo; exit 0 ;;
  esac
fi

echo "Using firewall: $ACTIVE_FW"
sleep 1

CURRENT_RULES="$(snapshot_firewall "$ACTIVE_FW")"
CURRENT_RULES_STRIPPED="$(echo "$CURRENT_RULES" | tr -d ' \t\n')"
BACKUP_PATH=""

if [[ -n "$CURRENT_RULES_STRIPPED" ]]; then
  if ask_yesno "Backup rules" "Existing firewall rules detected.\nBack up current rules before making changes?"; then
    BACKUP_PATH="$(backup_firewall_rules "$ACTIVE_FW" "$CURRENT_RULES")"
    [[ -n "$BACKUP_PATH" ]] && echo "Backup saved to $BACKUP_PATH" || echo "No backup created."
  fi
fi

ALLOWED_RULES=(); DENIED_RULES=()

# --- default policy via whiptail ---
POLICY="$(ask_menu "Default policy" "Choose default policy for incoming traffic:" \
          "deny"  "Block all by default (recommended)" \
          "allow" "Allow all by default")" || POLICY="deny"

case "$ACTIVE_FW" in
  ufw)
    if [[ "$POLICY" = "deny" ]]; then ufw default deny incoming; ufw default allow outgoing; else ufw default allow incoming; ufw default allow outgoing; fi
    ufw enable <<<"y"
    ;;
  firewalld)
    [[ "$POLICY" = "deny" ]] && firewall-cmd --set-default-zone=drop || firewall-cmd --set-default-zone=public
    firewall-cmd --reload
    ;;
  nftables)
    ensure_nftables_chains
    [[ "$POLICY" = "deny" ]] && { nft chain inet filter input '{ policy drop; }'; nft chain inet filter forward '{ policy drop; }'; } \
                              || { nft chain inet filter input '{ policy accept; }'; nft chain inet filter forward '{ policy accept; }'; }
    nft chain inet filter output '{ policy accept; }'
    ;;
  iptables)
    if [[ "$POLICY" = "deny" ]]; then iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
    else iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT; fi
    ;;
esac

ensure_ssh_access
echo "Default policy set to: ${POLICY^^}"

auto_allow_ssh_port() {
  local port="$1"; [[ -n "$port" ]] || return
  [[ "$POLICY" != "deny" ]] && { echo "SSH port ${port}/tcp permitted by default policy."; return; }
  case "$ACTIVE_FW" in
    ufw)       ufw allow "${port}/tcp" >/dev/null 2>&1 && echo "Ensured SSH ${port}/tcp via ufw." ;;
    firewalld) firewall-cmd --add-port="${port}/tcp" --permanent >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 && echo "Ensured SSH ${port}/tcp via firewalld." ;;
    nftables)  ensure_nftables_chains; nft list chain inet filter input 2>/dev/null | grep -Eq "tcp dport ${port} .*accept" || { nft add rule inet filter input tcp dport "$port" counter accept >/dev/null 2>&1; echo "Ensured SSH ${port}/tcp via nftables."; } ;;
    iptables)  iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || { iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; echo "Ensured SSH ${port}/tcp via iptables."; } ;;
  esac
}
auto_allow_ssh_port "$SSH_PORT"

# --- interactive rule editor with whiptail ---
ACTION_LABEL=$( [[ "$POLICY" = "deny" ]] && echo "ALLOW" || echo "DENY")
RULE_ACTION=$( [[ "$POLICY" = "deny" ]] && echo "allow" || echo "deny")

while ask_yesno "Edit rules" "Do you want to ${ACTION_LABEL} a port or service group?"; do
  selection="$(ask_input "Select services/ports" "Enter a service group name (e.g. web) or a space-separated list of ports (e.g. 22 443/tcp 8080):")" || selection=""
  selection="$(trim "$selection")"
  [[ -z "$selection" ]] && continue

  # quick help
  if [[ "${selection,,}" == "list" ]]; then
    whiptail --backtitle "Raffo Setup" --title "Service groups" --msgbox "$(list_service_groups)" 20 70
    continue
  fi

  # expand group -> ports
  group_name=""
  port_specs=()
  if [[ -n "${SERVICE_GROUPS[${selection,,}]:-}" ]]; then
    group_name="${selection,,}"
    read -r -a port_specs <<< "${SERVICE_GROUPS[$group_name]}"
  else
    read -r -a port_specs <<< "$selection"
  fi
  [[ ${#port_specs[@]} -eq 0 ]] && continue

  SOURCE_INPUT="$(ask_input "Source filter" "Limit to a specific source IP/CIDR (leave empty for any):" "" || true)"
  SOURCE_INPUT="$(trim "${SOURCE_INPUT:-}")"

  for port_spec in "${port_specs[@]}"; do
    port_spec="$(trim "$port_spec")"; [[ -z "$port_spec" ]] && continue
    read -r PORT_NUMBER PROTOCOL <<<"$(parse_port_spec "$port_spec")"
    PORT_NUMBER="$(trim "$PORT_NUMBER")"; PROTOCOL="${PROTOCOL,,}"
    [[ -z "$PORT_NUMBER" || -z "$PROTOCOL" ]] && continue
    if [[ "$RULE_ACTION" == "deny" && "$PORT_NUMBER" == "22" && "$PROTOCOL" == "tcp" ]]; then
      continue
    fi
    apply_rule "$RULE_ACTION" "$PORT_NUMBER" "$PROTOCOL" "$SOURCE_INPUT"
    desc="${PORT_NUMBER}/${PROTOCOL}"; [[ -n "$SOURCE_INPUT" ]] && desc+=" from $SOURCE_INPUT"; [[ -n "$group_name" ]] && desc+=" (group: $group_name)"
    if [[ "$RULE_ACTION" == "allow" ]]; then ALLOWED_RULES+=("$desc"); else DENIED_RULES+=("$desc"); fi
  done
done

# --- persistence + summary (same logic as yours) ---
PERSIST_MESSAGE=""; IPTABLES_PERSISTENCE_NOTE=""
case "$ACTIVE_FW" in
  firewalld)
    if [[ ${ensure_firewalld_reload:-0} -eq 1 ]]; then
      firewall-cmd --reload && PERSIST_MESSAGE="firewalld configuration reloaded with permanent changes." || PERSIST_MESSAGE="firewalld reload failed; please reload manually."
    fi
    ;;
  nftables)
    NFT_CONF="/etc/nftables.conf"
    nft list ruleset >"$NFT_CONF" 2>/dev/null && PERSIST_MESSAGE="nftables rules saved to $NFT_CONF." || PERSIST_MESSAGE="Failed to save nftables rules to $NFT_CONF; please review permissions."
    ;;
  iptables)
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null && PERSIST_MESSAGE="iptables rules saved to /etc/iptables/rules.v4" || PERSIST_MESSAGE="Failed to save IPv4 rules to /etc/iptables/rules.v4"
    if command -v ip6tables-save >/dev/null 2>&1; then
      ip6tables-save > /etc/iptables/rules.v6 2>/dev/null && PERSIST_MESSAGE+="; IPv6 rules saved to /etc/iptables/rules.v6." || PERSIST_MESSAGE+="; failed to save IPv6 rules."
    else
      PERSIST_MESSAGE+="; ip6tables not available."
    fi
    if command -v dpkg >/dev/null 2>&1 && ! dpkg -s iptables-persistent >/dev/null 2>&1; then
      if DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent; then
        IPTABLES_PERSISTENCE_NOTE="Installed iptables-persistent for persistence."
      else
        IPTABLES_PERSISTENCE_NOTE="Failed to install iptables-persistent; please install manually."
      fi
    else
      IPTABLES_PERSISTENCE_NOTE="${IPTABLES_PERSISTENCE_NOTE:-iptables-persistent already installed.}"
    fi
    ;;
esac

SUMMARY_LINES=()
SUMMARY_LINES+=("$(date -Iseconds) Firewall summary")
SUMMARY_LINES+=("  Backend: $ACTIVE_FW")
SUMMARY_LINES+=("  Default policy: ${POLICY^^}")
SUMMARY_LINES+=("  SSH access: ensured (22/tcp allowed)")
[[ -n "$BACKUP_PATH" ]] && SUMMARY_LINES+=("  Backup saved to: $BACKUP_PATH")
if [[ ${#ALLOWED_RULES[@]} -gt 0 ]]; then SUMMARY_LINES+=("  Allowed exceptions:"); for r in "${ALLOWED_RULES[@]}"; do SUMMARY_LINES+=("    - $r"); done; fi
if [[ ${#DENIED_RULES[@]} -gt 0 ]]; then SUMMARY_LINES+=("  Denied exceptions:");  for r in "${DENIED_RULES[@]}";  do SUMMARY_LINES+=("    - $r"); done; fi
[[ ${#ALLOWED_RULES[@]} -eq 0 && ${#DENIED_RULES[@]} -eq 0 ]] && SUMMARY_LINES+=("  No additional rule exceptions defined.")
[[ -n "$PERSIST_MESSAGE" ]] && SUMMARY_LINES+=("  Persistence: $PERSIST_MESSAGE")
[[ -n "$IPTABLES_PERSISTENCE_NOTE" ]] && SUMMARY_LINES+=("  $IPTABLES_PERSISTENCE_NOTE")

echo; echo "Firewall configuration summary:"
for line in "${SUMMARY_LINES[@]}"; do echo "$line"; log_summary "$line"; done
echo "Firewall configuration complete."
