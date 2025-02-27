#!/bin/bash

# Exit immediately if a command exits with a non-zero status
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
LOG_FILE="/var/log/yolink-update.log"

# Redirect all output to log file
exec > >(tee -i "$LOG_FILE")
exec 2>&1

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Functions for backup and restore
backup_file() {
  local FILE="$1"
  local BACKUP="$2"
  if [ -f "$FILE" ]; then
    cp "$FILE" "$BACKUP" || { echo "Failed to backup $(basename "$FILE")"; exit 1; }
    echo "$(basename "$FILE") backed up."
  else
    echo "Warning: $(basename "$FILE") does not exist. Skipping backup."
  fi
}

restore_file() {
  local BACKUP="$1"
  local FILE="$2"
  if [ -f "$BACKUP" ]; then
    mv "$BACKUP" "$FILE" || { echo "Failed to restore $(basename "$FILE")"; exit 1; }
    echo "$(basename "$FILE") restored."
  else
    echo "Warning: Backup not found. $(basename "$FILE") was not restored."
  fi
}

# Navigate to the app directory
cd "$APP_DIR" || { echo "Failed to navigate to app directory."; exit 1; }

# Backup current config files
backup_file "$CONFIG_FILE" "$CONFIG_BACKUP"
backup_file "$MAPPINGS_FILE" "$MAPPINGS_BACKUP"
backup_file "$DEVICES_FILE" "$DEVICES_BACKUP"

# Download and unzip the latest code
echo "Downloading latest code..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || { echo "Repository download failed."; exit 1; }
echo "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || { echo "Unzip failed."; exit 1; }

# Update files while preserving configs
echo "Updating application files..."
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || { echo "Move extracted files failed."; exit 1; }

# Restore configuration files
restore_file "$CONFIG_BACKUP" "$CONFIG_FILE"
restore_file "$MAPPINGS_BACKUP" "$MAPPINGS_FILE"
restore_file "$DEVICES_BACKUP" "$DEVICES_FILE"

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"

# Set permissions
echo "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { echo "Failed to set permissions."; exit 1; }
chmod +x "$APP_DIR/self-update.sh" || { echo "Failed to set executable permission."; exit 1; }

# Rebuild Docker containers
echo "Rebuilding Docker containers..."
docker compose down || { echo "Docker Compose down failed."; exit 1; }
docker compose up --build -d || { echo "Docker Compose up failed."; exit 1; }

# Verify config.html in container
container_name=$(docker ps --filter "name=yolink_chekt" --format '{{.Names}}')
if [ -z "$container_name" ]; then
  echo "Error: Service container not found."
  exit 1
fi
if docker exec "$container_name" test -f "/app/templates/config.html"; then
  echo "config.html successfully copied into the container."
else
  echo "Error: config.html not found in the container."
  exit 1
fi

echo "Update applied successfully!"