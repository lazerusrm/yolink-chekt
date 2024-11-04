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
TEMPLATES_DIR="$APP_DIR/templates"
DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"

# Function to handle errors
handle_error() {
  echo "Error: $1" >&2
  exit 1
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to install a package using apt-get
install_package() {
  PACKAGE_NAME="$1"
  echo "Installing $PACKAGE_NAME..."
  apt-get install -y "$PACKAGE_NAME" || handle_error "Failed to install $PACKAGE_NAME."
  echo "$PACKAGE_NAME installed successfully."
}

# Function to install Docker using the official Docker installation script
install_docker() {
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh || handle_error "Failed to download Docker installation script."
  sh get-docker.sh || handle_error "Failed to install Docker."
  rm get-docker.sh
  echo "Docker installed successfully."
}

# Function to install Docker Compose as a Docker plugin
install_docker_compose() {
  echo "Installing Docker Compose..."
  DOCKER_COMPOSE_VERSION="v2.20.3"  # Specify the desired version
  mkdir -p /usr/lib/docker/cli-plugins/
  curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/lib/docker/cli-plugins/docker-compose || handle_error "Failed to download Docker Compose."
  chmod +x /usr/lib/docker/cli-plugins/docker-compose
  ln -s /usr/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose || handle_error "Failed to create symlink for Docker Compose."
  echo "Docker Compose installed successfully."
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  handle_error "This script must be run as root."
fi

# Update package list
echo "Updating package list..."
apt-get update || handle_error "Failed to update package list."

# Check and install required dependencies
DEPENDENCIES=("curl" "unzip" "rsync")
for pkg in "${DEPENDENCIES[@]}"; do
  if ! command_exists "$pkg"; then
    install_package "$pkg"
  else
    echo "$pkg is already installed."
  fi
done

# Check and install Docker
if ! command_exists "docker"; then
  install_docker
else
  echo "Docker is already installed."
fi

# Check and install Docker Compose
if ! command_exists "docker-compose"; then
  install_docker_compose
else
  echo "Docker Compose is already installed."
fi

# Create required directories if they do not exist
echo "Ensuring application directories exist..."
mkdir -p "$APP_DIR" "$TEMPLATES_DIR" || handle_error "Failed to create application directories."

# Backup current config.yaml if it exists
backup_file() {
  local FILE="$1"
  local BACKUP="$2"
  if [ -f "$FILE" ]; then
    cp "$FILE" "$BACKUP" || handle_error "Failed to backup $(basename "$FILE")"
    echo "$(basename "$FILE") backed up."
  else
    echo "Warning: $(basename "$FILE") does not exist. Skipping backup."
  fi
}

backup_file "$CONFIG_FILE" "$CONFIG_BACKUP"
backup_file "$MAPPINGS_FILE" "$MAPPINGS_BACKUP"
backup_file "$DEVICES_FILE" "$DEVICES_BACKUP"

# Download and unzip the latest code from the repository
echo "Downloading latest code..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || handle_error "Repository download failed."

echo "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || handle_error "Unzip failed."

# Restore configuration files after update
restore_file() {
  local BACKUP="$1"
  local FILE="$2"
  if [ -f "$BACKUP" ]; then
    mv "$BACKUP" "$FILE" || handle_error "Failed to restore $(basename "$FILE") from backup"
    echo "$(basename "$FILE") restored."
  else
    echo "Warning: Backup not found. $(basename "$FILE") was not restored."
  fi
}

restore_file "$CONFIG_BACKUP" "$CONFIG_FILE"
restore_file "$MAPPINGS_BACKUP" "$MAPPINGS_FILE"
restore_file "$DEVICES_BACKUP" "$DEVICES_FILE"

# Move extracted files while excluding config.yaml, mappings.yaml, and devices.yaml
echo "Updating application files..."
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || handle_error "Move extracted files failed."

# Set appropriate permissions for the self-update script
chmod +x "$APP_DIR/self-update.sh" || handle_error "Setting executable permission failed."

# Clean up temporary files
echo "Cleaning up temporary files..."
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
