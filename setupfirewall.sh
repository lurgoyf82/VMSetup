#!/bin/bash

echo "=== Firewall configuration ==="

# === state/summary helpers ===
RAFFO_STATE_DIR=${RAFFO_STATE_DIR:-/var/lib/raffosetup}
RAFFO_BACKUP_DIR=${RAFFO_BACKUP_DIR:-$RAFFO_STATE_DIR/backups}
SETUP_SUMMARY_FILE=${SETUP_SUMMARY_FILE:-$RAFFO_STATE_DIR/setup-summary.txt}

mkdir -p "$RAFFO_STATE_DIR" "$RAFFO_BACKUP_DIR"

raffo_timestamp() {
  date +%Y%m%d%H%M%S
}

log_summary() {
  local line="$1"
  mkdir -p "$(dirname "$SETUP_SUMMARY_FILE")"
  echo "$line" >>"$SETUP_SUMMARY_FILE"
}

trim() {
  local var="$1"
  var="${var#${var%%[![:space:]]*}}"
  var="${var%${var##*[![:space:]]}}"
  echo "$var"
}

SSH_PORT_STATE_FILE="/var/lib/raffosetup/ssh_port"
SSH_PORT=""
if [[ -f "$SSH_PORT_STATE_FILE" ]]; then
  SSH_PORT=$(tr -d '\n\r\t ' <"$SSH_PORT_STATE_FILE")
fi

# helper functions for port parsing and nftables configuration
parse_port_spec() {
  local spec="$1"
  local proto="tcp"
  local port="$spec"

  if [[ "$spec" == */* ]]; then
    proto="${spec##*/}"
    port="${spec%/*}"
  fi

  echo "$port $proto"
}

ensure_nftables_chains() {
  nft list table inet filter >/dev/null 2>&1 || nft add table inet filter

  nft list chain inet filter input >/dev/null 2>&1 || \
    nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'

  nft list chain inet filter forward >/dev/null 2>&1 || \
    nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'

  nft list chain inet filter output >/dev/null 2>&1 || \
    nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'
}

snapshot_firewall() {
  case "$1" in
    ufw)
      ufw status numbered 2>/dev/null || true
      ;;
    firewalld)
      firewall-cmd --list-all-zones 2>/dev/null || true
      ;;
    nftables)
      nft list ruleset 2>/dev/null || true
      ;;
    iptables)
      { iptables-save 2>/dev/null; ip6tables-save 2>/dev/null; } || true
      ;;
  esac
}

backup_firewall_rules() {
  local backend="$1" data="$2"
  [[ -z "$data" ]] && return 0
  local path="$RAFFO_BACKUP_DIR/firewall-${backend}-$(raffo_timestamp).rules"
  printf '%s\n' "$data" >"$path"
  chmod 600 "$path"
  echo "$path"
}

ensure_firewalld_reload=0

declare -A SERVICE_GROUPS=(
  [ssh]="22/tcp"
  [http]="80/tcp"
  [https]="443/tcp"
  [web]="80/tcp 443/tcp"
  [http-alt]="8080/tcp"
  [dns]="53/tcp 53/udp"
  [ntp]="123/udp"
  [smtp]="25/tcp"
  [pop3]="110/tcp"
  [imap]="143/tcp"
)

declare -a ALLOWED_RULES
declare -a DENIED_RULES

list_service_groups() {
  echo "Available service groups:"
  for name in "${!SERVICE_GROUPS[@]}"; do
    printf '  - %s (%s)\n' "$name" "${SERVICE_GROUPS[$name]}"
  done | sort
}

ensure_ssh_access() {
  case "$ACTIVE_FW" in
    ufw)
      ufw allow "22/tcp" >/dev/null 2>&1 || ufw allow ssh
      ;;
    firewalld)
      firewall-cmd --add-service=ssh --permanent >/dev/null 2>&1 && ensure_firewalld_reload=1
      firewall-cmd --add-service=ssh >/dev/null 2>&1 || true
      ;;
    nftables)
      ensure_nftables_chains
      local rule_exists
      rule_exists=$(nft list chain inet filter input 2>/dev/null | grep -F "tcp dport 22" || true)
      if [[ -z "$rule_exists" ]]; then
        nft add rule inet filter input tcp dport 22 counter accept
      fi
      ;;
    iptables)
      if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT
      fi
      if command -v ip6tables >/dev/null 2>&1; then
        if ! ip6tables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
          ip6tables -I INPUT -p tcp --dport 22 -j ACCEPT
        fi
      fi
      ;;
  esac
}

firewalld_rich_rule_family() {
  local source="$1"
  if [[ -z "$source" ]]; then
    echo "ipv4"
  elif [[ "$source" == *:* ]]; then
    echo "ipv6"
  else
    echo "ipv4"
  fi
}

apply_rule() {
  local action="$1" port_number="$2" protocol="$3" source="$4"
  local proto_flag="$protocol"
  local family
  case "$ACTIVE_FW" in
    ufw)
      local ufw_action
      if [[ "$action" == "allow" ]]; then
        ufw_action="allow"
      else
        ufw_action="deny"
      fi
      if [[ -n "$source" ]]; then
        ufw "$ufw_action" from "$source" to any port "$port_number" proto "$proto_flag"
      else
        ufw "$ufw_action" "$port_number/$proto_flag"
      fi
      ;;
    firewalld)
      ensure_firewalld_reload=1
      if [[ "$action" == "allow" ]]; then
        if [[ "$port_number" == "22" && "$protocol" == "tcp" && -z "$source" ]]; then
          firewall-cmd --add-service=ssh --permanent >/dev/null 2>&1
          firewall-cmd --add-service=ssh >/dev/null 2>&1 || true
        elif [[ -n "$source" ]]; then
          family=$(firewalld_rich_rule_family "$source")
          local allow_rule="rule family=${family} source address=${source} port protocol=${protocol} port=${port_number} accept"
          firewall-cmd --add-rich-rule="$allow_rule" --permanent
          firewall-cmd --add-rich-rule="$allow_rule" >/dev/null 2>&1 || true
        else
          firewall-cmd --add-port="${port_number}/${protocol}" --permanent
          firewall-cmd --add-port="${port_number}/${protocol}" >/dev/null 2>&1 || true
        fi
      else
        family=$(firewalld_rich_rule_family "$source")
        if [[ -n "$source" ]]; then
          local drop_rule="rule family=${family} source address=${source} port protocol=${protocol} port=${port_number} drop"
          firewall-cmd --add-rich-rule="$drop_rule" --permanent
          firewall-cmd --add-rich-rule="$drop_rule" >/dev/null 2>&1 || true
        else
          local drop_rule_v4="rule family=ipv4 port protocol=${protocol} port=${port_number} drop"
          local drop_rule_v6="rule family=ipv6 port protocol=${protocol} port=${port_number} drop"
          firewall-cmd --add-rich-rule="$drop_rule_v4" --permanent
          firewall-cmd --add-rich-rule="$drop_rule_v6" --permanent
          firewall-cmd --add-rich-rule="$drop_rule_v4" >/dev/null 2>&1 || true
          firewall-cmd --add-rich-rule="$drop_rule_v6" >/dev/null 2>&1 || true
        fi
      fi
      ;;
    nftables)
      ensure_nftables_chains
      local source_clause=""
      if [[ -n "$source" ]]; then
        if [[ "$source" == *:* ]]; then
          source_clause="ip6 saddr ${source}"
        else
          source_clause="ip saddr ${source}"
        fi
      fi
      if [[ "$action" == "allow" ]]; then
        nft add rule inet filter input ${source_clause} ${protocol} dport ${port_number} counter accept
      else
        nft add rule inet filter input ${source_clause} ${protocol} dport ${port_number} counter drop
      fi
      ;;
    iptables)
      local table_cmd="iptables"
      local ip6=0
      local -a cmd_args=("-p" "$protocol" "--dport" "$port_number")
      if [[ -n "$source" ]]; then
        cmd_args+=("-s" "$source")
        [[ "$source" == *:* ]] && ip6=1
      fi
      if [[ "$action" == "allow" ]]; then
        if [[ $ip6 -eq 1 ]]; then
          if command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT "${cmd_args[@]}" -j ACCEPT 2>/dev/null; then
              ip6tables -I INPUT "${cmd_args[@]}" -j ACCEPT
            fi
          fi
        else
          if ! iptables -C INPUT "${cmd_args[@]}" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT "${cmd_args[@]}" -j ACCEPT
          fi
        fi
      else
        if [[ $ip6 -eq 1 ]]; then
          if command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT "${cmd_args[@]}" -j DROP 2>/dev/null; then
              ip6tables -I INPUT "${cmd_args[@]}" -j DROP
            fi
          fi
        else
          if ! iptables -C INPUT "${cmd_args[@]}" -j DROP 2>/dev/null; then
            iptables -I INPUT "${cmd_args[@]}" -j DROP
          fi
        fi
      fi
      ;;
  esac
}

# detect active firewall
ACTIVE_FW=$(for svc in ufw firewalld nftables iptables; do
  systemctl is-active --quiet "$svc" && echo "$svc"
done | head -n1)

if [ -z "$ACTIVE_FW" ]; then
  echo "No active firewall detected."
  read -p "Which one do you want to enable? [ufw/firewalld/nftables/iptables/none]: " CHOICE
  case "$CHOICE" in
    ufw|firewalld|nftables|iptables)
      systemctl enable --now "$CHOICE" 2>/dev/null || echo "Could not enable $CHOICE."
      ACTIVE_FW="$CHOICE"
      ;;
    *)
      echo "No firewall selected."
      exit 0
      ;;
  esac
fi

echo "Using firewall: $ACTIVE_FW"
sleep 1

CURRENT_RULES="$(snapshot_firewall "$ACTIVE_FW")"
CURRENT_RULES_STRIPPED="$(echo "$CURRENT_RULES" | tr -d ' \t\n')"
BACKUP_PATH=""

if [[ -n "$CURRENT_RULES_STRIPPED" ]]; then
  echo "Existing firewall rules detected."
  read -p "Do you want to back up the current rules before making changes? [yes(y)/no(n)]: " BACKUP_CHOICE
  case "$BACKUP_CHOICE" in
    y|Y|yes|YES)
      BACKUP_PATH="$(backup_firewall_rules "$ACTIVE_FW" "$CURRENT_RULES")"
      if [[ -n "$BACKUP_PATH" ]]; then
        echo "Backup saved to $BACKUP_PATH"
      else
        echo "No backup created."
      fi
      ;;
    *)
      echo "Skipping firewall backup."
      ;;
  esac
else
  CURRENT_RULES=""
fi

ALLOWED_RULES=()
DENIED_RULES=()

# === global policy ===
read -p "Default policy: block all (deny) or allow all (allow)? [deny/allow]: " POLICY
POLICY=${POLICY,,}   # lowercase

if [[ "$POLICY" != "deny" && "$POLICY" != "allow" ]]; then
  echo "Unknown policy '$POLICY', defaulting to deny."
  POLICY="deny"
fi

NFT_CONF="/etc/nftables.conf"

case "$ACTIVE_FW" in
  ufw)
    if [ "$POLICY" = "deny" ]; then
      ufw default deny incoming
      ufw default allow outgoing
    else
      ufw default allow incoming
      ufw default allow outgoing
    fi
    ufw enable <<< "y"
    ;;
  firewalld)
    if [ "$POLICY" = "deny" ]; then
      firewall-cmd --set-default-zone=drop
    else
      firewall-cmd --set-default-zone=public
    fi
    firewall-cmd --reload
    ;;
  nftables)
    ensure_nftables_chains
    if [ "$POLICY" = "deny" ]; then
      nft chain inet filter input '{ policy drop; }'
      nft chain inet filter forward '{ policy drop; }'
    else
      nft chain inet filter input '{ policy accept; }'
      nft chain inet filter forward '{ policy accept; }'
    fi
    nft chain inet filter output '{ policy accept; }'
    ;;
  iptables)
    if [ "$POLICY" = "deny" ]; then
      iptables -P INPUT DROP
      iptables -P FORWARD DROP
      iptables -P OUTPUT ACCEPT
    else
      iptables -P INPUT ACCEPT
      iptables -P FORWARD ACCEPT
      iptables -P OUTPUT ACCEPT
    fi
    ;; 
esac

ensure_ssh_access

echo "Default policy set to: ${POLICY^^}"

auto_allow_ssh_port() {
  local port="$1"
  [[ -n "$port" ]] || return
  if [ "$POLICY" != "deny" ]; then
    echo "SSH port ${port}/tcp permitted by default policy."
    return
  fi

  case "$ACTIVE_FW" in
    ufw)
      ufw allow "${port}/tcp" >/dev/null 2>&1 && \
        echo "Ensured SSH port ${port}/tcp allowed via ufw."
      ;;
    firewalld)
      firewall-cmd --add-port="${port}/tcp" --permanent >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 && \
        echo "Ensured SSH port ${port}/tcp allowed via firewalld."
      ;;
    nftables)
      ensure_nftables_chains
      if ! nft list chain inet filter input 2>/dev/null | grep -Eq "tcp dport ${port} .*accept"; then
        nft add rule inet filter input tcp dport "$port" counter accept >/dev/null 2>&1 && \
          echo "Ensured SSH port ${port}/tcp allowed via nftables."
      fi
      ;;
    iptables)
      if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 && \
          echo "Ensured SSH port ${port}/tcp allowed via iptables."
      fi
      ;;
  esac
}

auto_allow_ssh_port "$SSH_PORT"

# === interactive loop for exceptions ===

ACTION_LABEL=$( [ "$POLICY" = "deny" ] && echo "ALLOW" || echo "DENY")
RULE_ACTION=$( [ "$POLICY" = "deny" ] && echo "allow" || echo "deny")

echo "You can reference service groups like: ${!SERVICE_GROUPS[@]}"
echo "Type 'list' to show groups or 'add' to create a new one."

while true; do
  echo
  read -p "Do you want to ${ACTION_LABEL} a port or service group? [yes(y)/no(n)]: " ANSW
  case "$ANSW" in
    y|Y|yes|YES)
      selection=""
      while true; do
        read -p "Enter service group or port (space separated e.g. 22 443/tcp 80 8080): " selection
        selection=$(trim "$selection")
        [[ -z "$selection" ]] && break
        selection_lower=${selection,,}
        if [[ "$selection_lower" == "list" || "$selection" == "?" ]]; then
          list_service_groups
          continue
        elif [[ "$selection_lower" == "add" ]]; then
          read -p "New group name: " new_group
          new_group=$(trim "$new_group")
          new_group=${new_group,,}
          if [[ -z "$new_group" ]]; then
            echo "Group name cannot be empty."
          else
            read -p "Ports for group '$new_group' (space separated e.g. 22 443/tcp 80 8080): " new_ports
            new_ports=$(trim "$new_ports")
            if [[ -n "$new_ports" ]]; then
              SERVICE_GROUPS[$new_group]="$new_ports"
              echo "Service group '$new_group' added: $new_ports"
            else
              echo "No ports provided; group not added."
            fi
          fi
          continue
        fi
        break
      done

      if [[ -z "$selection" ]]; then
        echo "No selection provided."
        continue
      fi

      selection_lower=${selection,,}
      group_name=""
      port_specs=()
      if [[ -n "${SERVICE_GROUPS[$selection_lower]:-}" ]]; then
        group_name="$selection_lower"
        read -r -a port_specs <<< "${SERVICE_GROUPS[$selection_lower]}"
      else
        read -r -a port_specs <<< "$selection"
      fi

      if [[ ${#port_specs[@]} -eq 0 ]]; then
        echo "No valid ports found for selection '$selection'."
        continue
      fi

      read -p "Limit rule to a specific source IP/CIDR (leave blank for any): " SOURCE_INPUT
      SOURCE_INPUT=$(trim "$SOURCE_INPUT")

      for port_spec in "${port_specs[@]}"; do
        port_spec=$(trim "$port_spec")
        [[ -z "$port_spec" ]] && continue
        read -r PORT_NUMBER PROTOCOL <<< "$(parse_port_spec "$port_spec")"
        PORT_NUMBER=$(trim "$PORT_NUMBER")
        PROTOCOL=${PROTOCOL,,}
        if [[ -z "$PORT_NUMBER" || -z "$PROTOCOL" ]]; then
          echo "Skipping invalid specification '$port_spec'."
          continue
        fi
        if [[ "$RULE_ACTION" == "deny" && "$PORT_NUMBER" == "22" && "$PROTOCOL" == "tcp" ]]; then
          echo "Skipping rule for SSH (22/tcp); SSH access must remain allowed."
          continue
        fi
        apply_rule "$RULE_ACTION" "$PORT_NUMBER" "$PROTOCOL" "$SOURCE_INPUT"
        desc="${PORT_NUMBER}/${PROTOCOL}"
        if [[ -n "$SOURCE_INPUT" ]]; then
          desc+=" from $SOURCE_INPUT"
        fi
        if [[ -n "$group_name" ]]; then
          desc+=" (group: $group_name)"
        fi
        if [[ "$RULE_ACTION" == "allow" ]]; then
          ALLOWED_RULES+=("$desc")
          echo "Allowed $desc"
        else
          DENIED_RULES+=("$desc")
          echo "Denied $desc"
        fi
      done
      ;;
    *)
      echo "No more rules to edit."
      break
      ;;
  esac
done

PERSIST_MESSAGE=""
IPTABLES_PERSISTENCE_NOTE=""

case "$ACTIVE_FW" in
  firewalld)
    if [[ ${ensure_firewalld_reload:-0} -eq 1 ]]; then
      if firewall-cmd --reload; then
        PERSIST_MESSAGE="firewalld configuration reloaded with permanent changes."
      else
        PERSIST_MESSAGE="firewalld reload failed; please reload manually."
      fi
    fi
    ;;
  nftables)
    if nft list ruleset >"$NFT_CONF" 2>/dev/null; then
      PERSIST_MESSAGE="nftables rules saved to $NFT_CONF."
    else
      PERSIST_MESSAGE="Failed to save nftables rules to $NFT_CONF; please review permissions."
    fi
    ;;
  iptables)
    mkdir -p /etc/iptables
    if iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
      PERSIST_MESSAGE="iptables rules saved to /etc/iptables/rules.v4"
    else
      PERSIST_MESSAGE="Failed to save IPv4 rules to /etc/iptables/rules.v4"
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
      if ip6tables-save > /etc/iptables/rules.v6 2>/dev/null; then
        PERSIST_MESSAGE+="; IPv6 rules saved to /etc/iptables/rules.v6."
      else
        PERSIST_MESSAGE+="; failed to save IPv6 rules."
      fi
    else
      PERSIST_MESSAGE+="; ip6tables not available."
    fi
    if command -v apt-get >/dev/null 2>&1; then
      if command -v dpkg >/dev/null 2>&1 && dpkg -s iptables-persistent >/dev/null 2>&1; then
        IPTABLES_PERSISTENCE_NOTE="iptables-persistent already installed."
      else
        if DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent; then
          IPTABLES_PERSISTENCE_NOTE="Installed iptables-persistent for persistence."
        else
          IPTABLES_PERSISTENCE_NOTE="Failed to install iptables-persistent; please install manually."
        fi
      fi
    else
      IPTABLES_PERSISTENCE_NOTE="Install iptables-persistent (or equivalent) manually to retain rules across reboots."
    fi
    ;;
esac

SUMMARY_LINES=()
SUMMARY_HEADER="$(date -Iseconds) Firewall summary"
SUMMARY_LINES+=("$SUMMARY_HEADER")
SUMMARY_LINES+=("  Backend: $ACTIVE_FW")
SUMMARY_LINES+=("  Default policy: ${POLICY^^}")
SUMMARY_LINES+=("  SSH access: ensured (22/tcp allowed)")
if [[ -n "$BACKUP_PATH" ]]; then
  SUMMARY_LINES+=("  Backup saved to: $BACKUP_PATH")
fi
if [[ ${#ALLOWED_RULES[@]} -gt 0 ]]; then
  SUMMARY_LINES+=("  Allowed exceptions:")
  for rule in "${ALLOWED_RULES[@]}"; do
    SUMMARY_LINES+=("    - $rule")
  done
fi
if [[ ${#DENIED_RULES[@]} -gt 0 ]]; then
  SUMMARY_LINES+=("  Denied exceptions:")
  for rule in "${DENIED_RULES[@]}"; do
    SUMMARY_LINES+=("    - $rule")
  done
fi
if [[ ${#ALLOWED_RULES[@]} -eq 0 && ${#DENIED_RULES[@]} -eq 0 ]]; then
  SUMMARY_LINES+=("  No additional rule exceptions defined.")
fi
if [[ -n "$PERSIST_MESSAGE" ]]; then
  SUMMARY_LINES+=("  Persistence: $PERSIST_MESSAGE")
fi
if [[ -n "$IPTABLES_PERSISTENCE_NOTE" ]]; then
  SUMMARY_LINES+=("  $IPTABLES_PERSISTENCE_NOTE")
fi

echo
echo "Firewall configuration summary:"
for line in "${SUMMARY_LINES[@]}"; do
  echo "$line"
  log_summary "$line"
done

echo "Firewall configuration complete."
