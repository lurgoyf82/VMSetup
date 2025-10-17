#!/usr/bin/env bash
set -euo pipefail

source /root/raffolib.sh

if ! command -v locale-gen >/dev/null 2>&1; then
  msg_error "locale-gen not available"
  exit 1
fi

SUPPORTED_FILE="/usr/share/i18n/SUPPORTED"
if [[ ! -r "$SUPPORTED_FILE" ]]; then
  msg_error "Supported locale list not found at $SUPPORTED_FILE"
  exit 1
fi

mapfile -t SUPPORTED_LOCALES < <(grep -v '^#' "$SUPPORTED_FILE" | awk '{print $1}' | sort -u)
if [[ ${#SUPPORTED_LOCALES[@]} -eq 0 ]]; then
  msg_error "No supported locales discovered"
  exit 1
fi

current_locale=""
if command -v localectl >/dev/null 2>&1; then
  current_locale=$(localectl status 2>/dev/null | awk -F': ' '/System Locale/ {print $2; exit}')
fi
if [[ -z "$current_locale" ]]; then
  current_locale=$(locale | awk -F'=' '/^LANG=/ {print $2; exit}')
fi
current_locale=${current_locale:-en_US.UTF-8}

msg_info "Current system locale: $current_locale"
msg_ok "Locale information loaded"

selected_locale=""
locale_selection_handled=0
if ask_yesno "System Locale" "Current locale: $current_locale\n\nDo you want to change the system locale?"; then
  mapfile -t LANGUAGE_GROUPS < <(printf '%s\n' "${SUPPORTED_LOCALES[@]}" | awk -F'[_.@]' '{print $1}' | sort -u)
  LANGUAGE_GROUPS+=("manual")

  while true; do
    language_menu_args=()
    for lang in "${LANGUAGE_GROUPS[@]}"; do
      if [[ "$lang" == "manual" ]]; then
        language_menu_args+=("manual" "Enter locale manually")
      else
        language_menu_args+=("$lang" "Locales starting with ${lang}_")
      fi
    done

    selected_language=$(ask_menu "Locale Language" \
      "Select the language group for the locale" \
      "${language_menu_args[@]}") || {
        msg_ok "Locale configuration skipped"
        locale_selection_handled=1
        selected_locale=""
        break
      }

    if [[ "$selected_language" == "manual" ]]; then
      manual_locale=$(ask_input "System Locale" "Enter locale (e.g. en_US.UTF-8)" "$current_locale") || manual_locale=""
      manual_locale="${manual_locale//[[:space:]]/}"
      if [[ -n "$manual_locale" ]]; then
        selected_locale="$manual_locale"
      else
        selected_locale=""
      fi
      break
    fi

    mapfile -t language_locales < <(printf '%s\n' "${SUPPORTED_LOCALES[@]}" | grep -E "^${selected_language}[_@.]" || true)
    if [[ ${#language_locales[@]} -eq 0 ]]; then
      msg_error "No locales found for $selected_language"
      continue
    fi

    locale_menu_args=()
    for loc in "${language_locales[@]}"; do
      locale_menu_args+=("$loc" " ")
    done

    selected_locale=$(ask_menu "System Locale" \
      "Select the desired locale" \
      "${locale_menu_args[@]}") || {
        msg_ok "Locale configuration skipped"
        locale_selection_handled=1
        selected_locale=""
      }
    break
  done
else
  msg_ok "Locale configuration skipped"
  locale_selection_handled=1
fi

if [[ -n "$selected_locale" && "$selected_locale" != "$current_locale" ]]; then
  if ! printf '%s\n' "${SUPPORTED_LOCALES[@]}" | grep -Fxq "$selected_locale"; then
    if ask_yesno "Unknown Locale" "Locale '$selected_locale' is not in the supported list.\n\nGenerate anyway?"; then
      msg_info "Generating locale $selected_locale"
      locale-gen "$selected_locale"
    else
      msg_ok "Locale generation cancelled"
      locale_selection_handled=1
      selected_locale=""
    fi
  else
    msg_info "Generating locale $selected_locale"
    locale-gen "$selected_locale"
  fi

  if [[ -n "$selected_locale" ]]; then
    msg_info "Updating system locale to $selected_locale"
    update-locale LANG="$selected_locale"
    if command -v localectl >/dev/null 2>&1; then
      localectl set-locale LANG="$selected_locale" >/dev/null 2>&1 || true
    fi
    msg_ok "Locale set to $selected_locale"
    locale_selection_handled=1
  fi
elif [[ -n "$selected_locale" ]]; then
  msg_ok "Locale already set to $selected_locale"
  locale_selection_handled=1
else
  if [[ $locale_selection_handled -eq 0 ]]; then
    msg_ok "Locale unchanged"
  fi
fi

if command -v localectl >/dev/null 2>&1; then
  current_layout=$(localectl status 2>/dev/null | awk -F': ' '/X11 Layout/ {print $2; exit}')
  current_variant=$(localectl status 2>/dev/null | awk -F': ' '/X11 Variant/ {print $2; exit}')
  current_layout=${current_layout:-us}

  if ask_yesno "Keyboard Layout" "Current layout: ${current_layout}${current_variant:+ ($current_variant)}\n\nDo you want to configure the keyboard layout?"; then
    new_layout=$(ask_input "Keyboard Layout" "Enter keyboard layout (e.g. us, de, fr)" "$current_layout") || new_layout=""
    new_layout="${new_layout//[[:space:]]/}"
    if [[ -n "$new_layout" ]]; then
      new_variant=$(ask_input "Keyboard Variant" "Enter keyboard variant (optional)" "$current_variant") || new_variant=""
      new_variant="${new_variant//[[:space:]]/}"
      msg_info "Applying keyboard layout ${new_layout}${new_variant:+ ($new_variant)}"
      if [[ -n "$new_variant" ]]; then
        localectl set-x11-keymap "$new_layout" "" "$new_variant"
      else
        localectl set-x11-keymap "$new_layout"
      fi
      msg_ok "Keyboard layout updated"
    else
      msg_ok "Keyboard layout unchanged"
    fi
  else
    msg_ok "Keyboard layout configuration skipped"
  fi
else
  msg_ok "localectl not available; skipping keyboard layout configuration"
fi
