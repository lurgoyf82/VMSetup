#!/usr/bin/env bash
set -euo pipefail
source /root/raffolib.sh

export DEBIAN_FRONTEND=noninteractive

msg_info "Refreshing package index"
apt-get update -y >/dev/null
msg_ok "Package index updated"

add_packages() {
  local pkg
  for pkg in "$@"; do
    SELECTED_PACKAGES["$pkg"]=1
  done
}

declare -A SELECTED_PACKAGES=()
add_packages curl wget vim nano htop jq git net-tools bmon traceroute

msg_info "Evaluating system entropy availability"
entropy_package=""
if [[ -r /proc/sys/kernel/random/entropy_avail ]]; then
  entropy_value=$(< /proc/sys/kernel/random/entropy_avail)
  if (( entropy_value < 2000 )); then
    for candidate in haveged rng-tools; do
      if apt-cache show "$candidate" >/dev/null 2>&1; then
        entropy_package="$candidate"
        break
      fi
    done
    if [[ -n "$entropy_package" ]]; then
      add_packages "$entropy_package"
      msg_ok "Entropy low ($entropy_value). Added $entropy_package"
    else
      msg_ok "Entropy low ($entropy_value). No supplemental package available"
    fi
  else
    msg_ok "Entropy level sufficient ($entropy_value)"
  fi
else
  msg_ok "Entropy availability not detectable"
fi

msg_info "Selecting optional package bundles"
bundle_selection=$(ask_checklist "Package Bundles" \
  "Select optional package bundles to install" \
  "diagnostics" "Diagnostics utilities (strace, ltrace, tcpdump, mtr-tiny, sysstat)" OFF \
  "build-essential" "Development toolchain (build-essential, pkg-config, dkms)" OFF) || bundle_selection=""

if [[ -n "$bundle_selection" ]]; then
  read -r -a bundle_array <<< "$bundle_selection"
  readable_bundles=()
  for raw_bundle in "${bundle_array[@]}"; do
    bundle=${raw_bundle//\"/}
    case "$bundle" in
      diagnostics)
        add_packages strace ltrace tcpdump mtr-tiny sysstat iperf3
        readable_bundles+=("Diagnostics")
        ;;
      build-essential)
        add_packages build-essential pkg-config dkms
        readable_bundles+=("Build-essential")
        ;;
    esac
  done
  msg_ok "Selected bundles: ${readable_bundles[*]}"
else
  msg_ok "No optional bundles selected"
fi

mapfile -t FINAL_PACKAGES < <(printf '%s\n' "${!SELECTED_PACKAGES[@]}" | sort)

msg_info "Installing ${#FINAL_PACKAGES[@]} packages"
apt-get install -y "${FINAL_PACKAGES[@]}"
msg_ok "Package installation complete"

log_file=$(raffo_module_log_path "setuppackages")
msg_info "Logging installed package list"
dpkg-query -W -f='${Package}\t${Version}\n' | sort > "$log_file"
msg_ok "Installed package list saved to $log_file"
