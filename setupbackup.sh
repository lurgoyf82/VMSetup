#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/raffolib.sh"

msg_info "Starting backup client configuration"

CLIENT=$(ask_menu "Backup Client" \
  "Select the backup client to configure" \
  "proxmox" "Proxmox Backup Client" \
  "borg" "BorgBackup" \
  "restic" "Restic" \
  "veeam" "Veeam Agent for Linux" \
  "cancel" "Cancel setup") || CLIENT="cancel"

if [[ "$CLIENT" == "cancel" ]]; then
  msg_error "Backup setup cancelled"
  exit 1
fi

case "$CLIENT" in
  proxmox)
    PACKAGE="proxmox-backup-client"
    CLIENT_LABEL="Proxmox Backup Client"
    SERVER_PROMPT="Enter the Proxmox Backup Server hostname or IP"
    REPO_PROMPT="Repository (user@pbs@host:datastore)"
    DEFAULT_TIMER="hourly"
    CREDENTIAL_GUIDANCE="Use 'proxmox-backup-client login --repository <repo>' to store API tokens securely under /root/.config/proxmox-backup."
    ;;
  borg)
    PACKAGE="borgbackup"
    CLIENT_LABEL="BorgBackup"
    SERVER_PROMPT="Enter the SSH host storing the Borg repository"
    REPO_PROMPT="Repository path (e.g. ssh://user@host/./repo)"
    DEFAULT_TIMER="daily"
    CREDENTIAL_GUIDANCE="Use borg key files or BORG_PASSCOMMAND; store passwords in root-only files under /root/.config/borg."
    ;;
  restic)
    PACKAGE="restic"
    CLIENT_LABEL="Restic"
    SERVER_PROMPT="Enter the Restic repository host or service"
    REPO_PROMPT="Repository URL (e.g. sftp:user@host:/path or s3:https://bucket)"
    DEFAULT_TIMER="daily"
    CREDENTIAL_GUIDANCE="Use RESTIC_PASSWORD_FILE or credential helpers stored with 600 permissions; secrets are not written by this script."
    ;;
  veeam)
    PACKAGE="veeam"
    CLIENT_LABEL="Veeam Agent for Linux"
    SERVER_PROMPT="Enter the Veeam Backup & Replication server"
    REPO_PROMPT="Backup policy name or repository label"
    DEFAULT_TIMER="daily"
    CREDENTIAL_GUIDANCE="Run 'veeamconfig session create' to store credentials in the Veeam configuration database (encrypted)."
    ;;
  *)
    msg_error "Unsupported selection"
    exit 1
    ;;
esac

SERVER=$(ask_input "Backup Server" "$SERVER_PROMPT")
REPOSITORY=$(ask_input "Repository" "$REPO_PROMPT")
SCHEDULE=$(ask_input "Timer" "Enter systemd OnCalendar schedule" "$DEFAULT_TIMER")

if [[ -z "$SERVER" || -z "$REPOSITORY" ]]; then
  msg_error "Server and repository details are required"
  exit 1
fi

msg_info "Refreshing package index"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
msg_ok "Package index ready"

msg_info "Installing $CLIENT_LABEL"
if ! apt-cache show "$PACKAGE" >/dev/null 2>&1; then
  msg_error "Package $PACKAGE not found in configured repositories"
  exit 1
fi
apt-get install -y "$PACKAGE"
msg_ok "$CLIENT_LABEL installed"

CLIENT_KEY=$(raffo_sanitize_key "$CLIENT")
CONFIG_DIR="/etc/raffosetup"
ENV_FILE="$CONFIG_DIR/backup-${CLIENT_KEY}.env"
SCRIPT_PATH="/usr/local/sbin/raffo-backup-test.sh"
SERVICE="/etc/systemd/system/raffo-backup-${CLIENT_KEY}.service"
TIMER="/etc/systemd/system/raffo-backup-${CLIENT_KEY}.timer"
LOG_FILE="$RAFFO_STATE_DIR/backup_setup.log"

msg_info "Writing configuration"
mkdir -p "$CONFIG_DIR"
OLD_UMASK="$(umask)"
umask 077
cat >"$ENV_FILE" <<EOF_ENV
BACKUP_CLIENT="$CLIENT_LABEL"
BACKUP_PACKAGE="$PACKAGE"
BACKUP_SERVER="$SERVER"
BACKUP_REPOSITORY="$REPOSITORY"
BACKUP_TIMER="$SCHEDULE"
EOF_ENV
chmod 600 "$ENV_FILE"
umask "$OLD_UMASK"
msg_ok "Configuration stored at $ENV_FILE"

if [[ ! -f "$SCRIPT_PATH" ]]; then
  msg_info "Installing backup test runner"
  cat >"$SCRIPT_PATH" <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/raffo-backup-test.log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
CLIENT="${BACKUP_CLIENT:-unknown}"
REPO="${BACKUP_REPOSITORY:-unspecified}"
PACKAGE="${BACKUP_PACKAGE:-}"
MESSAGE="$(date --iso-8601=seconds) - Test backup task for ${CLIENT} targeting ${REPO}"
if [[ -n "$PACKAGE" ]]; then
  BIN="$(command -v "$PACKAGE" 2>/dev/null || true)"
  if [[ -z "$BIN" ]]; then
    case "$PACKAGE" in
      proxmox-backup-client)
        BIN="$(command -v proxmox-backup-client 2>/dev/null || true)"
        ;;
      veeam)
        BIN="$(command -v veeamconfig 2>/dev/null || true)"
        ;;
    esac
  fi
  if [[ -n "$BIN" ]]; then
    "$BIN" --version >/dev/null 2>&1 || "$BIN" version >/dev/null 2>&1 || true
  fi
fi
echo "$MESSAGE" >>"$LOG_FILE"
EOF_SCRIPT
  chmod 750 "$SCRIPT_PATH"
  msg_ok "Test runner installed"
fi

msg_info "Configuring systemd service"
cat >"$SERVICE" <<EOF_SERVICE
[Unit]
Description=Raffo Backup Test (${CLIENT_LABEL})
After=network.target

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=$SCRIPT_PATH
EOF_SERVICE

cat >"$TIMER" <<EOF_TIMER
[Unit]
Description=Raffo Backup Test Timer (${CLIENT_LABEL})

[Timer]
OnCalendar=$SCHEDULE
Persistent=true
Unit=$(basename "$SERVICE")

[Install]
WantedBy=timers.target
EOF_TIMER

systemctl daemon-reload
systemctl enable --now "$(basename "$TIMER")"
msg_ok "Timer $(basename "$TIMER") enabled"

mkdir -p "$(dirname "$LOG_FILE")"
{
  echo "$(date --iso-8601=seconds) [$CLIENT_LABEL] Server: $SERVER Repository: $REPOSITORY"
  echo "$(date --iso-8601=seconds) [$CLIENT_LABEL] Credentials: $CREDENTIAL_GUIDANCE"
  echo "$(date --iso-8601=seconds) [$CLIENT_LABEL] Timer schedule: $SCHEDULE"
} >>"$LOG_FILE"
msg_ok "Guidance logged to $LOG_FILE"

raffo_mark_done "setupbackup"
msg_ok "Backup client setup completed"
