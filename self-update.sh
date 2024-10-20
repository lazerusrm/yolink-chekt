#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"
CONFIG_FILE="$APP_DIR/config.yaml"
CONFIG_BACKUP="$APP_DIR/config.yaml.bak"
MAPPINGS_FILE="$APP_DIR/mappings.yaml"
MAPPINGS_BACKUP="$APP_DIR/mappings.yaml.bak"
TEMPLATES_DIR="$APP_DIR/templates"  # Folder where HTML files like config.html are stored
DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"
LOG_FILE="$APP_DIR/self-update.log"

# Function to log messages
log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Function to handle errors
handle_error() {
    log_message "Error: $1"
    exit 1
}

# Backup current config.yaml if it exists
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$CONFIG_BACKUP" || handle_error "Failed to backup config.yaml"
    log_message "config.yaml backed up."
else
    log_message "Warning: config.yaml does not exist. Skipping backup."
fi

# Backup current mappings.yaml if it exists
if [ -f "$MAPPINGS_FILE" ]; then
    cp "$MAPPINGS_FILE" "$MAPPINGS_BACKUP" || handle_error "Failed to backup mappings.yaml"
    log_message "mappings.yaml backed up."
else
    log_message "Warning: mappings.yaml does not exist. Skipping backup."
fi

# Download and unzip the latest code from the repository
log_message "Downloading latest code..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || handle_error "Repository download failed."

log_message "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || handle_error "Unzip failed."

# Restore configuration files after update
if [ -f "$CONFIG_BACKUP" ]; then
    mv "$CONFIG_BACKUP" "$CONFIG_FILE" || handle_error "Failed to restore config.yaml from backup"
    log_message "config.yaml restored."
else
    log_message "Warning: Backup not found. config.yaml was not restored."
fi

if [ -f "$MAPPINGS_BACKUP" ]; then
    mv "$MAPPINGS_BACKUP" "$MAPPINGS_FILE" || handle_error "Failed to restore mappings.yaml from backup"
    log_message "mappings.yaml restored."
else
    log_message "Warning: Backup not found. mappings.yaml was not restored."
fi

# Move extracted files while excluding config.yaml and mappings.yaml
log_message "Updating application files..."
if ! command -v rsync &> /dev/null; then
    handle_error "rsync not found. Please install rsync."
fi

rsync -a --exclude='config.yaml' --exclude='mappings.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || handle_error "Move extracted files failed."
log_message "Application files updated."

# Set appropriate permissions for the self-update script
chmod +x "$APP_DIR/self-update.sh" || handle_error "Setting executable permission failed."
log_message "Permissions set for self-update script."

# Clean up temporary files
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"
log_message "Temporary files cleaned up."

# Rebuild Docker containers with the latest code
log_message "Rebuilding Docker containers..."
docker compose down || handle_error "Docker Compose down failed."
docker compose up --build -d || handle_error "Docker Compose up failed."
log_message "Docker containers rebuilt."

# Check if the config.html file is in the container after the rebuild
container_name=$(docker ps --filter "name=yolink_chekt" --format '{{.Names}}')
if [ -z "$container_name" ]; then
    handle_error "Service container not found."
fi

# Verify config.html inside container
if docker exec "$container_name" test -f "/app/templates/config.html"; then
    log_message "config.html successfully copied into the container."
else
    handle_error "config.html not found in the container."
fi

log_message "Updates applied successfully!"
echo "Updates applied successfully!"
