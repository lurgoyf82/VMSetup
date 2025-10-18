#!/bin/bash
# RaffoLib — shared variables and functions for Raffo Setup

# enable whiptail helpers when available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v whiptail >/dev/null 2>&1; then
  source "$SCRIPT_DIR/raffolib.sh"
  USE_WHIPTAIL=1
else
  USE_WHIPTAIL=0
fi

set -euo pipefail
shopt -s inherit_errexit nullglob extglob

# === paths ===
RAFFO_STATE_DIR=${RAFFO_STATE_DIR:-/var/lib/raffosetup}
RAFFO_BACKUP_DIR=${RAFFO_BACKUP_DIR:-$RAFFO_STATE_DIR/backups}
mkdir -p "$RAFFO_STATE_DIR"

# === colors ===
RD=$(echo "\033[01;31m")
YW=$(echo "\033[33m")
GN=$(echo "\033[1;92m")
BL=$(echo "\033[1;34m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="-"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# === profile globals ===
declare -Ag RAFFO_PROFILE=()
RAFFO_PROFILE_SOURCE=""
RAFFO_PROFILE_ERROR=""

# === utility helpers ===
raffo_timestamp() {
  date +%Y%m%d%H%M%S
}

raffo_backup_path() {
  local SOURCE="$1"; local LABEL="${2:-}"
  local NAME
  if [[ -n "$LABEL" ]]; then
    NAME="$LABEL"
  else
    NAME="$(basename "$SOURCE")"
  fi
  local TS="$(raffo_timestamp)"
  mkdir -p "$RAFFO_BACKUP_DIR"
  echo "$RAFFO_BACKUP_DIR/${NAME}.${TS}"
}

raffo_backup() {
  local SOURCE="$1"; local LABEL="${2:-}"
  if [[ ! -e "$SOURCE" ]]; then
    echo ""; return 1
  fi
  local DEST
  DEST="$(raffo_backup_path "$SOURCE" "$LABEL")"
  if [[ -d "$SOURCE" ]]; then
    cp -a "$SOURCE" "$DEST"
  else
    cp -a "$SOURCE" "$DEST"
  fi
  echo "$DEST"
}

raffo_marker_path() {
  local MODULE="$(raffo_sanitize_key "$1")"
  echo "$RAFFO_STATE_DIR/${MODULE}.done"
}

raffo_mark_done() {
  local MODULE="$1"
  mkdir -p "$RAFFO_STATE_DIR"
  touch "$(raffo_marker_path "$MODULE")"
}

raffo_is_done() {
  local MODULE="$1"
  [[ -f "$(raffo_marker_path "$MODULE")" ]]
}

raffo_clear_marker() {
  local MODULE="$1"
  rm -f "$(raffo_marker_path "$MODULE")"
}

raffo_sanitize_key() {
  local KEY="${1,,}"
  KEY="${KEY//[^a-z0-9_-]/_}"
  KEY="${KEY##_}"
  KEY="${KEY%%_}"
  echo "$KEY"
}

raffo_module_id() {
  local SCRIPT="${1:-}"; local TITLE="${2:-}"
  local BASE=""
  if [[ -n "$SCRIPT" ]]; then
    BASE="$(basename "$SCRIPT")"
    BASE="${BASE%.*}"
  fi
  if [[ -z "$BASE" && -n "$TITLE" ]]; then
    BASE="$TITLE"
  fi
  raffo_sanitize_key "$BASE"
}

raffo_module_log_path() {
  local MODULE_ID="$(raffo_sanitize_key "$1")"
  echo "/tmp/raffo_${MODULE_ID}.log"
}

raffo_profile_set() {
  local KEY="$(raffo_sanitize_key "$1")"
  local VALUE="$2"
  RAFFO_PROFILE["$KEY"]="$VALUE"
}

raffo_profile_choice() {
  local MODULE_KEY="$(raffo_sanitize_key "$1")"
  local VALUE="${RAFFO_PROFILE[$MODULE_KEY]:-}"
  if [[ -z "$VALUE" ]]; then
    local ENV_KEY="RAFFO_${MODULE_KEY^^}"
    VALUE="${!ENV_KEY:-}"
  fi
  echo "$VALUE"
}

raffo_trim() {
  local STR="$1"
  STR="${STR##+([[:space:]])}"
  STR="${STR%%+([[:space:]])}"
  echo "$STR"
}

raffo_parse_env_profile() {
  local FILE="$1"
  while IFS='=' read -r RAW_KEY RAW_VALUE; do
    [[ -z "$RAW_KEY" ]] && continue
    [[ "$RAW_KEY" =~ ^[[:space:]]*# ]] && continue
    local KEY="$(raffo_trim "$RAW_KEY")"
    local VALUE="$(raffo_trim "${RAW_VALUE%%#*}")"
    VALUE="${VALUE#\"}"; VALUE="${VALUE%\"}"
    VALUE="${VALUE#\'}"; VALUE="${VALUE%\'}"
    [[ -z "$KEY" ]] && continue
    raffo_profile_set "$KEY" "$VALUE"
  done <"$FILE"
}

raffo_parse_json_stream() {
  while IFS='=' read -r KEY VALUE; do
    [[ -z "$KEY" ]] && continue
    raffo_profile_set "$KEY" "$VALUE"
  done
}

raffo_load_profile() {
  local BASE="/etc/raffosetup"
  local CANDIDATES=("$BASE/profile.env" "$BASE/profile.json" "$BASE/profile.yaml" "$BASE/profile.yml")
  local FILE=""
  for C in "${CANDIDATES[@]}"; do
    if [[ -f "$C" ]]; then
      FILE="$C"
      break
    fi
  done
  if [[ -z "$FILE" ]]; then
    RAFFO_PROFILE_SOURCE=""
    RAFFO_PROFILE_ERROR=""
    return 1
  fi

  case "$FILE" in
    *.env)
      raffo_parse_env_profile "$FILE" || {
        RAFFO_PROFILE_ERROR="Failed to parse $FILE"
        return 2
      }
      ;;
    *.json)
      if ! command -v jq >/dev/null 2>&1; then
        RAFFO_PROFILE_ERROR="jq is required to parse $FILE"
        return 2
      fi
      jq -r 'if has("modules") and (.modules | type=="object") then .modules else . end | to_entries | map("\(.key)=\(.value|tostring)") | .[]' "$FILE" |
        raffo_parse_json_stream || {
          RAFFO_PROFILE_ERROR="Failed to parse $FILE"
          return 2
        }
      ;;
    *.yaml|*.yml)
      if ! command -v jq >/dev/null 2>&1; then
        RAFFO_PROFILE_ERROR="jq is required to parse $FILE"
        return 2
      fi
      if command -v yq >/dev/null 2>&1; then
        yq -o=json "$FILE" |
          jq -r 'if has("modules") and (.modules | type=="object") then .modules else . end | to_entries | map("\(.key)=\(.value|tostring)") | .[]' |
          raffo_parse_json_stream || {
            RAFFO_PROFILE_ERROR="Failed to parse $FILE"
            return 2
          }
      else
        RAFFO_PROFILE_ERROR="yq is required to parse YAML profile $FILE"
        return 2
      fi
      ;;
    *)
      RAFFO_PROFILE_ERROR="Unsupported profile format: $FILE"
      return 2
      ;;
  esac

  RAFFO_PROFILE_SOURCE="$FILE"
  return 0
}

# === messages ===
msg_info()  { echo -ne " ${HOLD} ${YW}${1}...${CL}"; }
msg_ok()    { echo -e "${BFR} ${CM} ${GN}${1}${CL}"; }
msg_error() { echo -e "${BFR} ${CROSS} ${RD}${1}${CL}"; }

# --- whiptail helpers ---
ask_yesno() {
  local TITLE="$1"; local MESSAGE="$2"
  whiptail --backtitle "Raffo Setup" --title "$TITLE" \
           --yesno "$MESSAGE" 12 65
}

ask_menu() {
  local TITLE="$1"; local MESSAGE="$2"; shift 2
  whiptail --backtitle "Raffo Setup" --title "$TITLE" \
           --menu "$MESSAGE" 15 60 6 "$@" 3>&2 2>&1 1>&3
}

ask_checklist() {
  local TITLE="$1"; local MESSAGE="$2"; shift 2
  whiptail --backtitle "Raffo Setup" --title "$TITLE" \
           --checklist "$MESSAGE" 16 60 8 "$@" 3>&2 2>&1 1>&3
}

ask_input() {
  local TITLE="$1"; local MESSAGE="$2"; local DEFAULT="${3:-}"
  whiptail --backtitle "Raffo Setup" --title "$TITLE" \
           --inputbox "$MESSAGE" 10 60 "$DEFAULT" 3>&1 1>&2 2>&3
}

# --- standardized step wrapper (Proxmox look) ---
run_step() {
  local TITLE="$1" MESSAGE="$2" SCRIPT="$3"
  local HEIGHT="${4:-14}" WIDTH="${5:-58}"
  local MODULE_ID="${6:-$(raffo_module_id "$SCRIPT" "$TITLE")}" 

  local CHOICE="${RAFFO_FORCED_CHOICE:-}"
  if [[ -z "$CHOICE" ]]; then
    CHOICE=$(
      whiptail --backtitle "Raffo Setup" --title "$TITLE" \
               --menu "$MESSAGE" "$HEIGHT" "$WIDTH" 2 \
               "yes" " " "no" " " 3>&2 2>&1 1>&3
    ) || CHOICE="no"
  fi
  unset RAFFO_FORCED_CHOICE

  local log="$(raffo_module_log_path "${MODULE_ID:-$(raffo_module_id "$SCRIPT" "$TITLE")}")"
  RAFFO_LAST_LOG="$log"
  local rc=0
  case "${CHOICE,,}" in
    yes|y|true|1)
      msg_info "Starting $TITLE"; echo
      local verbose="${RAFFO_VERBOSE:-0}"
      mkdir -p "$(dirname "$log")"
      if [[ "$verbose" == "1" ]]; then
        bash "$SCRIPT" 2>&1 | tee -a "$log"
        rc=${PIPESTATUS[0]}
      else
        # keep whiptail on its tty but log all other output
        bash "$SCRIPT" > >(tee -a "$log") 2>&1
        rc=${PIPESTATUS[0]}
      fi
      if [[ $rc -eq 0 ]]; then
        msg_ok "$TITLE completed successfully"
      else
        msg_error "$TITLE failed (exit $rc)"
        echo -e "${YW}Hint: tail -n20 \"${log}\"${CL}"
        [[ "$verbose" == "1" ]] || \
          echo -e "${YW}See ${log} for details.${CL}"
      fi
      ;;
    no|n|false|0|skip)
      msg_error "$TITLE skipped"
      rc=200
      ;;
    *)
      msg_error "$TITLE skipped"
      rc=200
      ;;
  esac
  return $rc
}

# === header ===
header_info() {
  clear
  cat <<"EOF"

    _____ __    ____        ____ ____      __      _____       __
   / ___// /   / __ \____ _/ __// __/____ /_/____ / ___/ ___  / /___  ______
  / ___// /   / /_/ / __ `/ __// __// __ \ / ___/ \__  \/ _ \/ __/ / / / __ \
 / /__ / /__ / _, _/ /_/ / /  / /  / /_/ /(__  )  ___/ /  __/ /_  /_/ / /_/ /
/____//____//_/ |_|\__,_/_/  /_/   \____//____/  /____/\___/\__/\__,_/ ____/
                                                                    /_/
                    Raffo Setup
EOF
  echo -e "${BL}Welcome to Raffo Setup!${CL}\n"
}
