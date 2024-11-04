#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"
CONFIG_FILE="$APP_DIR/config.yaml"
CONFIG_BACKUP="$APP_DIR/config.yaml.bak"
MAPPINGS_FILE="$APP_DIR/mappings.yaml"
MAPPINGS_BACKUP="$APP_DIR/mappings.yaml.bak"
DEVICES_FILE="$APP_DIR/devices.yaml"
DEVICES_BACKUP="$APP_DIR/devices.yaml.bak"
TEMPLATES_DIR="$APP_DIR/templates"
DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"

# Function to handle errors
handle_error() {
  echo "Error: $1"
  exit 1
}

# Function to check and install a dependency if it is missing
check_and_install() {
  if ! command -v "$1" &> /dev/null; then
    echo "$1 not found. Installing $1..."
    apt-get update && apt-get install -y "$1" || handle_error "Failed to install $1."
    echo "$1 installed successfully."
  fi
}

# Check and install required dependencies
check_and_install curl
check_and_install unzip
check_and_install rsync

# Create required directories if they do not exist
echo "Ensuring application directories exist..."
mkdir -p "$APP_DIR" "$TEMPLATES_DIR" || handle_error "Failed to create application directories."

# Backup current config.yaml if it exists
if [ -f "$CONFIG_FILE" ]; then
  cp "$CONFIG_FILE" "$CONFIG_BACKUP" || handle_error "Failed to backup config.yaml"
  echo "config.yaml backed up."
else
  echo "Warning: config.yaml does not exist. Skipping backup."
fi

# Backup current mappings.yaml if it exists
if [ -f "$MAPPINGS_FILE" ]; then
  cp "$MAPPINGS_FILE" "$MAPPINGS_BACKUP" || handle_error "Failed to backup mappings.yaml"
  echo "mappings.yaml backed up."
else
  echo "Warning: mappings.yaml does not exist. Skipping backup."
fi

# Backup current devices.yaml if it exists
if [ -f "$DEVICES_FILE" ]; then
  cp "$DEVICES_FILE" "$DEVICES_BACKUP" || handle_error "Failed to backup devices.yaml"
  echo "devices.yaml backed up."
else
  echo "Warning: devices.yaml does not exist. Skipping backup."
fi

# Download and unzip the latest code from the repository
echo "Downloading latest code..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || handle_error "Repository download failed."

echo "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || handle_error "Unzip failed."

# Restore configuration files after update
if [ -f "$CONFIG_BACKUP" ]; then
  mv "$CONFIG_BACKUP" "$CONFIG_FILE" || handle_error "Failed to restore config.yaml from backup"
  echo "config.yaml restored."
else
  echo "Warning: Backup not found. config.yaml was not restored."
fi

if [ -f "$MAPPINGS_BACKUP" ]; then
  mv "$MAPPINGS_BACKUP" "$MAPPINGS_FILE" || handle_error "Failed to restore mappings.yaml from backup"
  echo "mappings.yaml restored."
else
  echo "Warning: Backup not found. mappings.yaml was not restored."
fi

if [ -f "$DEVICES_BACKUP" ]; then
  mv "$DEVICES_BACKUP" "$DEVICES_FILE" || handle_error "Failed to restore devices.yaml from backup"
  echo "devices.yaml restored."
else
  echo "Warning: Backup not found. devices.yaml was not restored."
fi

# Move extracted files while excluding config.yaml, mappings.yaml, and devices.yaml
echo "Updating application files..."
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || handle_error "Move extracted files failed."

# Set appropriate permissions for the self-update script
chmod +x "$APP_DIR/self-update.sh" || handle_error "Setting executable permission failed."

# Clean up temporary files
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"

# Rebuild Docker containers with the latest code
echo "Rebuilding Docker containers..."
docker compose down || handle_error "Docker Compose down failed."
docker compose up --build -d || handle_error "Docker Compose up failed."

# Check if the config.html file is in the container after the rebuild
container_name=$(docker ps --filter "name=yolink_chekt" --format '{{.Names}}')
if [ -z "$container_name" ]; then
  handle_error "Service container not found."
fi

# Verify config.html inside container
if docker exec "$container_name" test -f "/app/templates/config.html"; then
  echo "config.html successfully copied into the container."
else
  handle_error "config.html not found in the container."
fi

echo "Updates applied successfully!"
