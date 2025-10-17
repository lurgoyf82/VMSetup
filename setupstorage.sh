#!/usr/bin/env bash
set -euo pipefail
source /root/raffolib.sh

require_commands() {
  local missing=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    msg_error "Missing required commands: ${missing[*]}"
    exit 1
  fi
}

append_report() {
  local header="$1"
  local content="$2"
  {
    echo "${header}"
    echo "${content}" | sed 's/^/  /'
    echo
  } >>"$REPORT_FILE"
}

expand_partition() {
  local disk="$1"
  local partnum="$2"
  msg_info "Expanding partition ${disk}${partnum}"
  if command -v growpart >/dev/null 2>&1; then
    growpart "$disk" "$partnum"
  else
    require_commands parted
    parted --script "$disk" resizepart "$partnum" 100%
  fi
  partprobe "$disk"
  msg_ok "Partition ${disk}${partnum} expanded"
}

resize_filesystem() {
  local device="$1"
  local fstype="$2"
  case "$fstype" in
    ext4)
      msg_info "Running resize2fs on $device"
      require_commands resize2fs
      resize2fs "$device"
      msg_ok "Filesystem on $device resized"
      ;;
    xfs)
      msg_info "Running xfs_growfs on /"
      require_commands xfs_growfs
      xfs_growfs -d /
      msg_ok "XFS filesystem expanded"
      ;;
    *)
      msg_error "Unsupported filesystem type: $fstype"
      return 1
      ;;
  esac
}

configure_swapfile() {
  local size_mb="$1"
  if [[ ! "$size_mb" =~ ^[0-9]+$ ]] || (( size_mb < 1 )); then
    msg_error "Invalid swap size"
    return 1
  fi
  msg_info "Configuring swapfile (${size_mb} MiB)"
  swapoff -a || true
  if [[ -f /swapfile ]]; then
    rm -f /swapfile
  fi
  fallocate -l "${size_mb}M" /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  if ! grep -q '^/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
  sed -i 's#^/swapfile.*#/swapfile none swap sw 0 0#' /etc/fstab
  msg_ok "Swapfile configured"
}

enable_zram() {
  msg_info "Enabling zram swap"
  apt-get update
  apt-get install -y zram-tools
  mkdir -p /etc/systemd/zram-generator.conf.d
  cat <<'ZCFG' >/etc/systemd/zram-generator.conf.d/raffo.conf
[zram0]
Compression=zstd
ZramSize=ram/2
ZCFG
  systemctl enable --now zramswap.service
  msg_ok "zram swap enabled"
}

setup_swap() {
  local current_swap
  current_swap=$(swapon --show --noheadings || true)
  local choice
  choice=$(ask_menu "Swap Configuration" "Select swap configuration option" \
    "keep" "Keep existing configuration" \
    "swapfile" "Create or resize swapfile" \
    "zram" "Enable zram-based swap") || choice="keep"
  case "$choice" in
    swapfile)
      local size
      size=$(ask_input "Swapfile Size" "Enter desired swap size in MiB" "2048") || size=""
      if [[ -z "$size" ]]; then
        msg_error "No swap size provided"
      else
        configure_swapfile "$size"
      fi
      ;;
    zram)
      enable_zram
      ;;
    *)
      msg_info "Keeping existing swap configuration"
      if [[ -n "$current_swap" ]]; then
        msg_ok "Current swap retained"
      else
        msg_ok "No swap configured"
      fi
      ;;
  esac
}

main() {
  require_commands lsblk findmnt partprobe swapon systemctl
  REPORT_FILE="$RAFFO_STATE_DIR/storage-report.txt"
  {
    echo "Storage expansion report - $(date)"
    echo
  } >"$REPORT_FILE"

  local initial_layout
  initial_layout=$(lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT)
  append_report "Initial layout:" "$initial_layout"

  local root_source root_device root_fstype root_type
  root_source=$(findmnt -no SOURCE /)
  root_fstype=$(findmnt -no FSTYPE /)
  root_device=$(readlink -f "$root_source")
  root_type=$(lsblk -no TYPE "$root_device")

  msg_info "Root device: $root_device ($root_type, $root_fstype)"

  if [[ "$root_type" == "lvm" ]]; then
    require_commands lvs pvs pvresize lvextend
    local vg_name lv_name
    read -r vg_name lv_name < <(lvs --noheadings -o vg_name,lv_name "$root_device" | awk '{print $1, $2}')
    msg_info "Detected LVM root on $vg_name/$lv_name"
    local pv_names
    mapfile -t pv_names < <(pvs --noheadings -o pv_name --select vg_name="$vg_name" | awk '{print $1}')
    if (( ${#pv_names[@]} != 1 )); then
      msg_error "Unsupported LVM layout (expected single PV)"
      exit 1
    fi
    local pv_device="${pv_names[0]}"
    local pv_real
    pv_real=$(readlink -f "$pv_device")
    local pv_type
    pv_type=$(lsblk -no TYPE "$pv_real")
    if [[ "$pv_type" != "part" ]]; then
      msg_error "PV $pv_real is not a partition (type: $pv_type)"
      exit 1
    fi
    local disk partnum pttype
    disk="/dev/$(lsblk -no PKNAME "$pv_real")"
    partnum=$(lsblk -no PARTNUM "$pv_real")
    pttype=$(lsblk -no PTTYPE "$disk")
    append_report "Partition table for $disk:" "Type: $pttype"
    expand_partition "$disk" "$partnum"
    msg_info "Running pvresize on $pv_real"
    pvresize "$pv_real"
    msg_ok "PV resized"
    msg_info "Extending LV to consume free space"
    lvextend -l +100%FREE "$root_device"
    msg_ok "LV extended"
    resize_filesystem "$root_device" "$root_fstype"
  elif [[ "$root_type" == "part" ]]; then
    local disk partnum pttype
    disk="/dev/$(lsblk -no PKNAME "$root_device")"
    partnum=$(lsblk -no PARTNUM "$root_device")
    pttype=$(lsblk -no PTTYPE "$disk")
    append_report "Partition table for $disk:" "Type: $pttype"
    expand_partition "$disk" "$partnum"
    resize_filesystem "$root_device" "$root_fstype"
  else
    msg_error "Unsupported root layout: $root_type"
    exit 1
  fi

  setup_swap

  msg_info "Enabling fstrim.timer"
  systemctl enable --now fstrim.timer
  msg_ok "fstrim.timer enabled"

  local final_layout
  final_layout=$(lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT)
  append_report "Final layout:" "$final_layout"
  local trim_status
  trim_status=$(systemctl status fstrim.timer --no-pager)
  append_report "fstrim.timer status:" "$trim_status"

  msg_ok "Storage setup complete. Report saved to $REPORT_FILE"
}

main "$@"
