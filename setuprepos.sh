#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

write_sources_stanza() {
  local target="$1" uri="$2" suite="$3" components="$4" signed_by="$5"
  {
    printf 'Types: deb\n'
    printf 'URIs: %s\n' "$uri"
    printf 'Suites: %s\n' "$suite"
    printf 'Components: %s\n' "$components"
    if [[ -n "$signed_by" ]]; then
      printf '%s\n' "$signed_by"
    fi
    printf '\n'
  } >>"$target"
}

msg_info "Detecting distribution release"
if [[ ! -f /etc/os-release ]]; then
  msg_error "Unable to locate /etc/os-release"
  exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

distro_id="${ID,,}"
codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
if [[ -z "$distro_id" || -z "$codename" ]]; then
  msg_error "Unable to determine distribution ID or codename"
  exit 1
fi

case "$distro_id" in
  debian|ubuntu)
    msg_ok "Detected $PRETTY_NAME ($codename)"
    ;;
  *)
    msg_error "Unsupported distribution: $PRETTY_NAME"
    exit 1
    ;;
esac

components=""
case "$distro_id" in
  debian)
    case "$codename" in
      bookworm|trixie|forky|sid)
        components="main contrib non-free non-free-firmware"
        ;;
      *)
        components="main contrib non-free"
        ;;
    esac
    ;;
  ubuntu)
    components="main restricted universe multiverse"
    ;;
  *)
    components="main"
    ;;
esac

choose_mirror() {
  local title="$1" message="$2" default_url="$3"
  shift 3
  local choice
  if ! choice=$(ask_menu "$title" "$message" "$@") 2>/dev/null; then
    choice="default"
  fi
  case "$choice" in
    default)
      printf '%s\n' "$default_url"
      ;;
    custom)
      local input
      if ! input=$(ask_input "$title" "Enter mirror URL" "$default_url") 2>/dev/null; then
        input="$default_url"
      fi
      printf '%s\n' "$(raffo_trim "$input")"
      ;;
    *)
      printf '%s\n' "$choice"
      ;;
  esac
}

msg_info "Selecting package mirrors"
case "$distro_id" in
  debian)
    default_mirror="https://deb.debian.org/debian"
    default_security="https://security.debian.org/debian-security"
    mirror=$(choose_mirror "Debian Mirror" "Select the primary Debian mirror" \
      "$default_mirror" \
      "default" "Worldwide CDN ($default_mirror)" \
      "https://ftp.debian.org/debian" "Primary Debian mirror" \
      "custom" "Custom mirror")
    security_mirror=$(choose_mirror "Debian Security Mirror" "Select the Debian security mirror" \
      "$default_security" \
      "default" "Official security mirror ($default_security)" \
      "https://deb.debian.org/debian-security" "Debian CDN security" \
      "custom" "Custom mirror")
    ;;
  ubuntu)
    default_mirror="https://archive.ubuntu.com/ubuntu"
    default_security="https://security.ubuntu.com/ubuntu"
    mirror=$(choose_mirror "Ubuntu Mirror" "Select the primary Ubuntu mirror" \
      "$default_mirror" \
      "default" "Official mirror ($default_mirror)" \
      "https://mirror.us.leaseweb.net/ubuntu" "Leaseweb US" \
      "custom" "Custom mirror")
    security_mirror="$default_security"
    ;;
esac
msg_ok "Using mirror: $mirror"
msg_ok "Using security mirror: $security_mirror"

msg_info "Backing up existing APT sources"
backup_paths=()
if [[ -f /etc/apt/sources.list ]]; then
  if dest=$(raffo_backup /etc/apt/sources.list apt-sources.list); then
    backup_paths+=("$dest")
  fi
fi
if [[ -d /etc/apt/sources.list.d ]]; then
  if dest=$(raffo_backup /etc/apt/sources.list.d apt-sources.list.d); then
    backup_paths+=("$dest")
  fi
fi
msg_ok "Backed up sources to: ${backup_paths[*]:-none}"

msg_info "Preparing deb822 sources"
mkdir -p /etc/apt/sources.list.d
rm -f /etc/apt/sources.list
shopt -s nullglob
for legacy in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.list.save; do
  rm -f "$legacy"
done
shopt -u nullglob

output_file="/etc/apt/sources.list.d/raffo-official.sources"
: >"$output_file"

signed_by=""
case "$distro_id" in
  debian)
    if [[ -f /usr/share/keyrings/debian-archive-keyring.gpg ]]; then
      signed_by="Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg"
    fi
    write_sources_stanza "$output_file" "$mirror" "$codename" "$components" "$signed_by"
    write_sources_stanza "$output_file" "$mirror" "${codename}-updates" "$components" "$signed_by"
    write_sources_stanza "$output_file" "$security_mirror" "${codename}-security" "$components" "$signed_by"
    ;;
  ubuntu)
    if [[ -f /usr/share/keyrings/ubuntu-archive-keyring.gpg ]]; then
      signed_by="Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
    fi
    write_sources_stanza "$output_file" "$mirror" "$codename" "$components" "$signed_by"
    write_sources_stanza "$output_file" "$mirror" "${codename}-updates" "$components" "$signed_by"
    write_sources_stanza "$output_file" "$security_mirror" "${codename}-security" "$components" "$signed_by"
    ;;
esac
msg_ok "deb822 sources written to $output_file"

current_proxy=""
proxy_file="/etc/apt/apt.conf.d/80proxy"
if [[ -f "$proxy_file" ]]; then
  current_proxy=$(awk -F'"' '/Acquire::http::Proxy/ {print $2}' "$proxy_file" || true)
fi

if ! proxy_value=$(ask_input "APT Proxy" "Enter HTTP proxy URL (leave blank for none)" "$current_proxy") 2>/dev/null; then
  proxy_value="$current_proxy"
fi
proxy_value="$(raffo_trim "$proxy_value")"

if [[ -n "$proxy_value" ]]; then
  msg_info "Configuring APT proxy"
  cat >"$proxy_file" <<PROXY
Acquire::http::Proxy "$proxy_value";
Acquire::https::Proxy "$proxy_value";
PROXY
  msg_ok "APT proxy set to $proxy_value"
else
  if [[ -f "$proxy_file" ]]; then
    msg_info "Removing existing APT proxy configuration"
    rm -f "$proxy_file"
    msg_ok "APT proxy removed"
  else
    msg_ok "No APT proxy configured"
  fi
fi

msg_info "Updating package lists"
export DEBIAN_FRONTEND=noninteractive
if apt-get update; then
  msg_ok "APT sources verified successfully"
else
  msg_error "apt-get update failed"
  exit 1
fi
