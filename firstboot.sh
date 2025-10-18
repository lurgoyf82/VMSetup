#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

header_info

if raffo_load_profile; then
  msg_ok "Loaded profile answers from ${RAFFO_PROFILE_SOURCE}"
else
  case $? in
    1)
      echo -e " ${HOLD} ${YW}No Raffo profile found; continuing interactively.${CL}"
      ;;
    *)
      msg_error "Failed to load profile: ${RAFFO_PROFILE_ERROR}"
      ;;
  esac
fi

declare -A MODULE_TITLES=()
declare -A MODULE_RESULTS=()
MODULE_ORDER=()

MODULE_DEFINITIONS=(
 "Network Configuration|Modify network interface addressing and DNS.\n \nDo you want to continue?|$SCRIPT_DIR/setupnetwork.sh"
 "Hostname Configuration|Set the system hostname and related DNS defaults.\n\nDo you want to continue?|$SCRIPT_DIR/setuphostname.sh"
 "Firewall Configuration|Tune firewall policies and per-port allowances.\n \nDo you want to continue?|$SCRIPT_DIR/setupfirewall.sh"
 "Logging Configuration|Configure journald persistence, limits, and optional forwarding.\n\nDo you want to continue?|$SCRIPT_DIR/setuplogging.sh"
 "System Updates|Refresh repositories and apply operating system updates before configuring other services.\n\nDo you want to continue?|$SCRIPT_DIR/setupupdates.sh"
 "Identity Reset|Regenerate machine identity data, host keys, and cached state.\n\nDo you want to continue?|$SCRIPT_DIR/setupidentity.sh"
 "Timezone|Pick the system timezone used for logs and shells.\n\nDo you want to continue?|$SCRIPT_DIR/setuptimezone.sh"
 "Time Synchronization|Choose the timezone and preferred NTP service, then verify clock synchronization.\n\nDo you want to continue?|$SCRIPT_DIR/setuptime.sh"
 "Locale & Keyboard|Configure system locales and keyboard layouts.\n\nDo you want to continue?|$SCRIPT_DIR/setuplocale.sh"
 "User Accounts|Create operators, reset passwords, and manage sudo access.\n\nDo you want to continue?|$SCRIPT_DIR/setupusers.sh"
 "SSH Hardening|Adjust SSH port, authentication policies, allow-lists, and keepalive tuning.\n\nDo you want to continue?|$SCRIPT_DIR/setupssh.sh"
 "Guest Agent|Install the matching guest agent for your hypervisor and configure serial console access when supported.\n\nDo you want to continue?|$SCRIPT_DIR/setupguestagent.sh"
 "Security Hardening|Apply kernel, service, and audit hardening controls.\n\nDo you want to continue?|$SCRIPT_DIR/setuphardening.sh"
)

for DEFINITION in "${MODULE_DEFINITIONS[@]}"; do
  IFS='|' read -r TITLE MESSAGE SCRIPT <<<"$DEFINITION"
  MODULE_ID="$(raffo_module_id "$SCRIPT" "$TITLE")"
  MODULE_TITLES["$MODULE_ID"]="$TITLE"
  MODULE_ORDER+=("$MODULE_ID")

  if raffo_is_done "$MODULE_ID"; then
    msg_ok "$TITLE already completed (marker present)"
    MODULE_RESULTS["$MODULE_ID"]=201
    continue
  fi

  PROFILE_CHOICE="$(raffo_profile_choice "$MODULE_ID")"
  PROFILE_APPLIED=0
  if [[ -n "$PROFILE_CHOICE" ]]; then
    case "${PROFILE_CHOICE,,}" in
      yes|y|true|1)
        RAFFO_FORCED_CHOICE="yes"
        PROFILE_APPLIED=1
        ;;
      no|n|false|0|skip)
        RAFFO_FORCED_CHOICE="no"
        PROFILE_APPLIED=1
        ;;
      *)
        echo -e " ${HOLD} ${YW}Profile value '$PROFILE_CHOICE' for ${TITLE} is unrecognized; prompting interactively.${CL}"
        ;;
    esac
  fi

  # run_step returns 0 (success), 200 (skipped), or non-zero (failure).
  # With `set -e` active (from raffolib.sh), a bare non-zero would exit the script,
  # so we must call it in a conditional to suppress errexit.
  set +e
  run_step "$TITLE" "$MESSAGE" "$SCRIPT" 14 58 "$MODULE_ID"
  RC=$?
  set -e
  MODULE_RESULTS["$MODULE_ID"]=$RC

  if [[ $RC -eq 0 ]]; then
    raffo_mark_done "$MODULE_ID"
  elif [[ $RC -eq 200 && $PROFILE_APPLIED -eq 1 ]]; then
    echo -e " ${HOLD} ${YW}${TITLE} skipped via profile.${CL}"
  fi
done

echo
printf '%b\n' "${BL}Module summary${CL}"
for MODULE_ID in "${MODULE_ORDER[@]}"; do
  TITLE="${MODULE_TITLES[$MODULE_ID]}"
  RC="${MODULE_RESULTS[$MODULE_ID]:-200}"
  case "$RC" in
    0)
      echo -e " ${CM} ${GN}${TITLE}${CL} (completed)"
      ;;
    200)
      echo -e " ${HOLD} ${YW}${TITLE}${CL} (skipped)"
      ;;
    201)
      echo -e " ${CM} ${GN}${TITLE}${CL} (already complete)"
      ;;
    *)
      LOG_PATH="$(raffo_module_log_path "$MODULE_ID")"
      echo -e " ${CROSS} ${RD}${TITLE}${CL} failed (exit ${RC})"
      echo -e "     ${YW}Log:${CL} ${LOG_PATH}"
      ;;
  esac

done

echo
printf '%b\n' "${YW}To rerun a module, remove its marker file and rerun Raffo Setup:${CL}"
for MODULE_ID in "${MODULE_ORDER[@]}"; do
  TITLE="${MODULE_TITLES[$MODULE_ID]}"
  MARKER="$(raffo_marker_path "$MODULE_ID")"
  echo -e "   rm -f ${MARKER}    ${YW}# ${TITLE}${CL}"
done

echo
if [[ -f "$SCRIPT_DIR/setupcleanup.sh" ]]; then
  if ! bash "$SCRIPT_DIR/setupcleanup.sh"; then
    msg_error "Cleanup and summary step failed. Review /var/log/raffosetup/cleanup.log"
  fi
else
  msg_error "Cleanup script missing: $SCRIPT_DIR/setupcleanup.sh"
fi

echo
if ask_yesno "Disable Autorun" "Disable Raffo Setup autorun at startup?"; then
  if sed -i 's|^\([^#].*firstboot\.sh.*\)$|# \1|' /root/.bashrc; then
    show_message "Autorun Disabled" "Raffo Setup autorun disabled.\n\nEnable again with:\n  sed -i 's|^#.*firstboot\\.sh.*|${SCRIPT_DIR}/firstboot.sh|' /root/.bashrc"
  else
    msg_error "Failed to disable Raffo Setup autorun."
  fi
else
  show_message "Autorun" "Raffo Setup autorun remains active."
fi
