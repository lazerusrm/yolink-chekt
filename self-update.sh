#!/bin/bash

# Exit on any error
set -e

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"
CONFIG_FILE="$APP_DIR/config.yaml"
CONFIG_BACKUP="$APP_DIR/config.yaml.bak"
MAPPINGS_FILE="$APP_DIR/mappings.yaml"
MAPPINGS_BACKUP="$APP_DIR/mappings.yaml.bak"
DEVICES_FILE="$APP_DIR/devices.yaml"
DEVICES_BACKUP="$APP_DIR/devices.yaml.bak"
LOG_DIR="/var/log"
LOG_FILE="$LOG_DIR/yolink-update.log"
MAX_RETRIES=3
RETRY_DELAY=5

# Ensure log directory exists
mkdir -p "$LOG_DIR" || { echo "Failed to create log directory $LOG_DIR"; exit 1; }
chmod 755 "$LOG_DIR"

# Redirect output to log file, fallback to /tmp if /var/log fails
if ! exec > >(tee -i "$LOG_FILE") 2>/dev/null; then
    LOG_FILE="/tmp/yolink-update.log"
    echo "Warning: Could not write to $LOG_FILE, falling back to $LOG_FILE"
    exec > >(tee -i "$LOG_FILE")
fi
exec 2>&1

# Timestamp for log entries
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Ensure script runs as root
if [ "$EUID" -ne 0 ]; then
    log "Error: This script must be run as root."
    exit 1
fi

# Backup function
backup_file() {
    local FILE="$1"
    local BACKUP="$2"
    if [ -f "$FILE" ]; then
        cp "$FILE" "$BACKUP" || { log "Error: Failed to backup $(basename "$FILE")"; exit 1; }
        log "Backed up $(basename "$FILE")"
    else
        log "Warning: $(basename "$FILE") does not exist, skipping backup"
    fi
}

# Restore function
restore_file() {
    local BACKUP="$1"
    local FILE="$2"
    if [ -f "$BACKUP" ]; then
        mv "$BACKUP" "$FILE" || { log "Error: Failed to restore $(basename "$FILE")"; exit 1; }
        log "Restored $(basename "$FILE")"
    else
        log "Warning: Backup for $(basename "$FILE") not found, skipping restore"
    fi
}

# Navigate to app directory
cd "$APP_DIR" || { log "Error: Failed to navigate to $APP_DIR"; exit 1; }
log "Working in $APP_DIR"

# Backup configuration files
backup_file "$CONFIG_FILE" "$CONFIG_BACKUP"
backup_file "$MAPPINGS_FILE" "$MAPPINGS_BACKUP"
backup_file "$DEVICES_FILE" "$DEVICES_BACKUP"

# Download with retry logic
download_with_retry() {
    local url="$1"
    local output="$2"
    local attempt=1
    while [ $attempt -le $MAX_RETRIES ]; do
        log "Downloading latest code (Attempt $attempt/$MAX_RETRIES)..."
        if curl -L "$url" -o "$output" 2>/tmp/curl_error; then
            log "Download successful"
            return 0
        else
            local curl_err=$(cat /tmp/curl_error)
            log "Download failed: $curl_err"
            if [ $attempt -eq $MAX_RETRIES ]; then
                log "Error: Repository download failed after $MAX_RETRIES attempts"
                exit 1
            fi
            sleep "$RETRY_DELAY"
            ((attempt++))
        fi
    done
}

# Download and unzip
download_with_retry "$REPO_URL" "$APP_DIR/repo.zip"
log "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || { log "Error: Unzip failed"; exit 1; }

# Update files while preserving configs
log "Updating application files..."
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || { log "Error: Move extracted files failed"; exit 1; }

# Restore configuration files
restore_file "$CONFIG_BACKUP" "$CONFIG_FILE"
restore_file "$MAPPINGS_BACKUP" "$MAPPINGS_FILE"
restore_file "$DEVICES_BACKUP" "$DEVICES_FILE"

# Clean up
log "Cleaning up temporary files..."
rm -rf "$APP_DIR/yolink-chekt-main" "$APP_DIR/repo.zip" /tmp/curl_error || log "Warning: Some cleanup failed"

# Set permissions
log "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { log "Error: Failed to set permissions"; exit 1; }
chmod +x "$APP_DIR/self-update.sh" || { log "Error: Failed to set executable permission"; exit 1; }

# Rebuild Docker containers
log "Rebuilding Docker containers..."
docker compose down || { log "Error: Docker Compose down failed"; exit 1; }
docker compose up --build -d || { log "Error: Docker Compose up failed"; exit 1; }

# Verify container and config.html
container_name=$(docker ps --filter "name=yolink_chekt" --format '{{.Names}}' | head -n 1)
if [ -z "$container_name" ]; then
    log "Error: Service container not found"
    exit 1
fi
if docker exec "$container_name" test -f "/app/templates/config.html"; then
    log "Verified: config.html present in container"
else
    log "Error: config.html not found in container"
    exit 1
fi

log "Update applied successfully!"