#!/bin/bash
# ============================================================
#  PPPC Analyzer — macOS Privacy & TCC Permission Inspector
#  Analyzes a .app bundle and reports required PPPC settings
#  Usage: ./pppc_analyzer.sh /Applications/Microsoft\ Teams.app
# ============================================================

set -euo pipefail

# ---------- Colors ----------
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
DIM='\033[2m'; RESET='\033[0m'; TICK='\033[0;32m✔\033[0m'
CROSS='\033[0;31m✘\033[0m'; WARN='\033[0;33m⚠\033[0m'

# ---------- Usage ----------
if [[ $# -lt 1 ]]; then
  echo ""
  echo "  ${BOLD}PPPC Analyzer${RESET} — macOS Privacy & TCC Permission Inspector"
  echo ""
  echo "  Usage: $0 /path/to/App.app"
  echo ""
  echo "  Examples:"
  echo "    $0 /Applications/Microsoft\\ Teams.app"
  echo "    $0 /Applications/zoom.us.app"
  echo "    $0 /Applications/Slack.app"
  echo ""
  exit 1
fi

APP_PATH="$1"

# Strip trailing slash
APP_PATH="${APP_PATH%/}"

# ---------- Validate ----------
if [[ ! -d "$APP_PATH" ]]; then
  echo -e "${RED}Error:${RESET} Not found: $APP_PATH"
  exit 1
fi

APP_NAME=$(basename "$APP_PATH" .app)
INFO_PLIST="$APP_PATH/Contents/Info.plist"
MACOS_BIN="$APP_PATH/Contents/MacOS"

echo ""
echo -e "  ${BOLD}${BLUE}PPPC Analyzer${RESET}"
echo -e "  ${DIM}macOS Privacy & TCC Permission Inspector${RESET}"
echo ""
echo -e "  ${BOLD}App:${RESET} $APP_NAME"
echo -e "  ${BOLD}Path:${RESET} $APP_PATH"
echo ""

# ─────────────────────────────────────────────
# 1. Bundle ID
# ─────────────────────────────────────────────
BUNDLE_ID=""
if [[ -f "$INFO_PLIST" ]]; then
  BUNDLE_ID=$(defaults read "$APP_PATH/Contents/Info" CFBundleIdentifier 2>/dev/null || true)
fi
if [[ -z "$BUNDLE_ID" ]]; then
  BUNDLE_ID=$(codesign -dvvv "$APP_PATH" 2>&1 | grep "^Identifier=" | cut -d= -f2 || true)
fi

echo -e "  ${BOLD}Bundle ID:${RESET}  ${CYAN}${BUNDLE_ID:-"(could not determine)"}${RESET}"

# ─────────────────────────────────────────────
# 2. Code Requirement
# ─────────────────────────────────────────────
CODE_REQ=$(codesign -dr - "$APP_PATH" 2>&1 | grep "^designated =>" | sed 's/designated => //' || true)
echo -e "  ${BOLD}Code Req:${RESET}   ${DIM}${CODE_REQ:-"(could not determine — run: codesign -dr - \"$APP_PATH\")"}${RESET}"

# ─────────────────────────────────────────────
# 3. Team ID
# ─────────────────────────────────────────────
TEAM_ID=$(codesign -dvvv "$APP_PATH" 2>&1 | grep "^TeamIdentifier=" | cut -d= -f2 || true)
echo -e "  ${BOLD}Team ID:${RESET}    ${DIM}${TEAM_ID:-"(not found)"}${RESET}"

echo ""
echo -e "  ${BOLD}── Entitlements ───────────────────────────────────${RESET}"

# ─────────────────────────────────────────────
# 4. Parse entitlements
# ─────────────────────────────────────────────
ENTITLEMENTS_RAW=$(codesign -d --entitlements - --xml "$APP_PATH" 2>/dev/null || true)

# Extract keys from entitlements XML
if [[ -n "$ENTITLEMENTS_RAW" ]]; then
  # Write to temp file for plutil
  TMPFILE=$(mktemp /tmp/pppc_entitlements_XXXXXX.plist)
  echo "$ENTITLEMENTS_RAW" > "$TMPFILE"
  ENTITLEMENT_KEYS=$(plutil -p "$TMPFILE" 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' | sort || true)
  rm -f "$TMPFILE"
else
  ENTITLEMENT_KEYS=""
fi

# ─────────────────────────────────────────────
# 5. Info.plist privacy keys
# ─────────────────────────────────────────────
PLIST_KEYS=""
if [[ -f "$INFO_PLIST" ]]; then
  PLIST_KEYS=$(plutil -p "$INFO_PLIST" 2>/dev/null | grep -oE '"NS[A-Za-z]*UsageDescription"' | tr -d '"' || true)
fi

# ─────────────────────────────────────────────
# Helper: check if key exists in list
# ─────────────────────────────────────────────
has_entitlement() {
  echo "$ENTITLEMENT_KEYS" | grep -qF "$1" 2>/dev/null
}
has_plist_key() {
  echo "$PLIST_KEYS" | grep -qF "$1" 2>/dev/null
}

# ─────────────────────────────────────────────
# 6. Permission Detection
# ─────────────────────────────────────────────
declare -a REQUIRED_PERMS=()
declare -a LIKELY_PERMS=()
declare -a POSSIBLE_PERMS=()

add_perm() {
  local level="$1" name="$2" tcc="$3" reason="$4"
  case "$level" in
    required) REQUIRED_PERMS+=("$name|$tcc|$reason") ;;
    likely)   LIKELY_PERMS+=("$name|$tcc|$reason") ;;
    possible) POSSIBLE_PERMS+=("$name|$tcc|$reason") ;;
  esac
}

already_in() {
  local name="$1"
  for p in "${REQUIRED_PERMS[@]:-}" "${LIKELY_PERMS[@]:-}" "${POSSIBLE_PERMS[@]:-}"; do
    [[ "$p" == "$name|"* ]] && return 0
  done
  return 1
}

# Camera
if has_entitlement "com.apple.security.device.camera" || has_plist_key "NSCameraUsageDescription"; then
  level="required"
  reason="Declares camera use"
  add_perm "$level" "Camera" "kTCCServiceCamera" "$reason"
fi

# Microphone
if has_entitlement "com.apple.security.device.microphone" || \
   has_entitlement "com.apple.security.device.audio-input" || \
   has_plist_key "NSMicrophoneUsageDescription"; then
  add_perm "required" "Microphone" "kTCCServiceMicrophone" "Declares mic use"
fi

# Screen Recording
if has_entitlement "com.apple.security.screen-recording"; then
  add_perm "required" "Screen Recording" "kTCCServiceScreenCapture" "Present"
fi

# Full Disk Access
if has_entitlement "com.apple.security.files.all" || \
   has_plist_key "NSSystemAdministrationUsageDescription"; then
  add_perm "required" "Full Disk Access" "kTCCServiceSystemPolicyAllFiles" "Declares full disk"
fi

# Accessibility
if has_entitlement "com.apple.security.accessibility"; then
  add_perm "required" "Accessibility" "kTCCServiceAccessibility" "Present"
fi

# Apple Events
if has_entitlement "com.apple.security.automation.apple-events" || \
   has_plist_key "NSAppleEventsUsageDescription"; then
  add_perm "required" "Apple Events / Automation" "kTCCServiceAppleEvents" "Declares Apple Events"
fi

# Downloads
if has_entitlement "com.apple.security.files.downloads.read-write" || \
   has_entitlement "com.apple.security.files.downloads.read-only" || \
   has_plist_key "NSDownloadsFolderUsageDescription"; then
  add_perm "likely" "Downloads Folder" "kTCCServiceSystemPolicyDownloadsFolder" "Declares downloads access"
fi

# Documents
if has_entitlement "com.apple.security.files.user-selected.read-write" || \
   has_plist_key "NSDocumentsFolderUsageDescription"; then
  add_perm "likely" "Documents Folder" "kTCCServiceSystemPolicyDocumentsFolder" "Declares documents"
fi

# Desktop
if has_plist_key "NSDesktopFolderUsageDescription"; then
  add_perm "likely" "Desktop Folder" "kTCCServiceSystemPolicyDesktopFolder" "Info.plist declares desktop access"
fi

# Contacts
if has_entitlement "com.apple.security.personal-information.addressbook" || \
   has_plist_key "NSContactsUsageDescription"; then
  add_perm "likely" "Contacts" "kTCCServiceAddressBook" "Declares contacts"
fi

# Calendar
if has_entitlement "com.apple.security.personal-information.calendars" || \
   has_plist_key "NSCalendarsUsageDescription"; then
  add_perm "likely" "Calendar" "kTCCServiceCalendars" "Declares calendar"
fi

# Reminders
if has_entitlement "com.apple.security.personal-information.reminders" || \
   has_plist_key "NSRemindersUsageDescription"; then
  add_perm "possible" "Reminders" "kTCCServiceReminders" "Plist declares reminders"
fi

# Location
if has_entitlement "com.apple.security.personal-information.location" || \
   has_plist_key "NSLocationUsageDescription" || \
   has_plist_key "NSLocationWhenInUseUsageDescription"; then
  add_perm "possible" "Location Services" "kTCCServiceLocation" "Declares location"
fi

# Photos
if has_entitlement "com.apple.security.personal-information.photos-library" || \
   has_plist_key "NSPhotoLibraryUsageDescription"; then
  add_perm "possible" "Photos Library" "kTCCServicePhotos" "Declares photo library"
fi

# Bluetooth
if has_plist_key "NSBluetoothAlwaysUsageDescription" || \
   has_plist_key "NSBluetoothPeripheralUsageDescription"; then
  add_perm "possible" "Bluetooth" "kTCCServiceBluetooth" "Plist declares Bluetooth"
fi

# ─────────────────────────────────────────────
# 7. Well-known app heuristics
# ─────────────────────────────────────────────
ID_LOWER=$(echo "${BUNDLE_ID:-}" | tr '[:upper:]' '[:lower:]')
NAME_LOWER=$(echo "$APP_NAME" | tr '[:upper:]' '[:lower:]')

# Microsoft Teams
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "teams"; then
  already_in "Camera"          || add_perm "required" "Camera"          "kTCCServiceCamera"         "Video calls"
  already_in "Microphone"      || add_perm "required" "Microphone"      "kTCCServiceMicrophone"     "Audio calls"
  already_in "Screen Recording"|| add_perm "required" "Screen Recording" "kTCCServiceScreenCapture"  "Screen sharing"
  already_in "Accessibility"   || add_perm "likely"   "Accessibility"   "kTCCServiceAccessibility"  "Keyboard shortcuts"
  already_in "Contacts"        || add_perm "likely"   "Contacts"        "kTCCServiceAddressBook"    "Contact search"
fi

# Zoom
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "zoom"; then
  already_in "Camera"          || add_perm "required" "Camera"          "kTCCServiceCamera"         "Video conferencing"
  already_in "Microphone"      || add_perm "required" "Microphone"      "kTCCServiceMicrophone"     "Audio conferencing"
  already_in "Screen Recording"|| add_perm "required" "Screen Recording" "kTCCServiceScreenCapture"  "Screen sharing"
  already_in "Accessibility"   || add_perm "required" "Accessibility"   "kTCCServiceAccessibility"  "Meeting controls"
fi

# Slack
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "slack"; then
  already_in "Camera"          || add_perm "likely" "Camera"          "kTCCServiceCamera"         "Huddles & video"
  already_in "Microphone"      || add_perm "likely" "Microphone"      "kTCCServiceMicrophone"     "Huddles & voice messages"
  already_in "Screen Recording"|| add_perm "likely" "Screen Recording" "kTCCServiceScreenCapture"  "Screen sharing"
  already_in "Downloads Folder"|| add_perm "likely" "Downloads Folder" "kTCCServiceSystemPolicyDownloadsFolder" "File downloads"
fi

# Chrome / Browser
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "chrome|firefox|brave|edge"; then
  already_in "Camera"           || add_perm "likely"   "Camera"          "kTCCServiceCamera"        "Web camera API"
  already_in "Microphone"       || add_perm "likely"   "Microphone"      "kTCCServiceMicrophone"    "Web mic API"
  already_in "Screen Recording" || add_perm "likely"   "Screen Recording" "kTCCServiceScreenCapture" "Screen sharing via browser"
  already_in "Downloads Folder" || add_perm "required" "Downloads Folder" "kTCCServiceSystemPolicyDownloadsFolder" "Browser downloads"
fi

# Jamf / MDM
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "jamf|mosyle|kandji|addigy|workspace.one"; then
  already_in "Full Disk Access" || add_perm "required" "Full Disk Access" "kTCCServiceSystemPolicyAllFiles" "MDM management"
  already_in "Accessibility"    || add_perm "required" "Accessibility"    "kTCCServiceAccessibility"        "Remote management"
fi

# CrowdStrike / SentinelOne / security agents
if echo "$ID_LOWER $NAME_LOWER" | grep -qiE "falcon|crowdstrike|sentinelone|cbdefense|carbonblack|cylance"; then
  already_in "Full Disk Access" || add_perm "required" "Full Disk Access" "kTCCServiceSystemPolicyAllFiles" "Security scanning"
fi

# ─────────────────────────────────────────────
# 8. Print Results
# ─────────────────────────────────────────────
print_section() {
  local title="$1" color="$2" symbol="$3" arr_name="$4"
  local len
  eval "len=\${#${arr_name}[@]}"
  if [[ $len -gt 0 ]]; then
    echo ""
    echo -e "  ${BOLD}${color}${title}${RESET}"
    local i
    for (( i=0; i<len; i++ )); do
      local item
      eval "item=\${${arr_name}[$i]}"
      IFS='|' read -r name tcc reason <<< "$item"
      printf "  %s  ${BOLD}%-28s${RESET} ${DIM}%-40s${RESET}  %s\n" \
        "$symbol" "$name" "$tcc" "$reason"
    done
  fi
}

TOTAL=$(( ${#REQUIRED_PERMS[@]} + ${#LIKELY_PERMS[@]} + ${#POSSIBLE_PERMS[@]} ))

if [[ $TOTAL -eq 0 ]]; then
  echo ""
  echo -e "  ${GREEN}${TICK} No PPPC permissions detected.${RESET}"
  echo -e "  ${DIM}No matching entitlements or Info.plist keys found.${RESET}"
else
  print_section "REQUIRED" "$RED"    "$(echo -e "${RED}●${RESET}")" REQUIRED_PERMS
  print_section "LIKELY"   "$ORANGE" "$(echo -e "${ORANGE}●${RESET}")" LIKELY_PERMS
  print_section "POSSIBLE" "$GREEN"  "$(echo -e "${GREEN}●${RESET}")" POSSIBLE_PERMS
fi
