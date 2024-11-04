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
LOG_FILE="/var/log/yolink-chekt-install.log"

# Redirect all output to log file
exec > >(tee -i "$LOG_FILE")
exec 2>&1

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
  ln -sf /usr/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose || handle_error "Failed to create symlink for Docker Compose."
  echo "Docker Compose installed successfully."
}

# Function to adjust security modules if necessary
adjust_security_modules() {
  echo "Checking security modules (AppArmor and SELinux)..."

  # Check AppArmor
  if command_exists aa-status; then
    aa_status=$(aa-status | grep "profiles are loaded")
    if [[ $aa_status == *"profiles are loaded"* ]]; then
      echo "AppArmor is active. Attempting to adjust Docker AppArmor profile."
      # Adjust Docker's AppArmor profile to allow necessary operations
      sudo aa-complain /etc/apparmor.d/docker || echo "Could not set Docker AppArmor profile to complain mode."
      echo "AppArmor adjustment completed."
    else
      echo "AppArmor is not active."
    fi
  else
    echo "AppArmor is not installed."
  fi

  # Check SELinux
  if command_exists sestatus; then
    selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
    if [[ $selinux_status == "enabled" ]]; then
      echo "SELinux is active. Setting to permissive mode temporarily."
      setenforce 0 || echo "Could not set SELinux to permissive mode."
      echo "SELinux set to permissive mode."
    else
      echo "SELinux is not enforcing."
    fi
  else
    echo "SELinux is not installed."
  fi
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

# Ensure Docker service is running
echo "Ensuring Docker service is running..."
systemctl enable docker || handle_error "Failed to enable Docker service."
systemctl start docker || handle_error "Failed to start Docker service."
echo "Docker service is running."

# Adjust security modules to prevent permission issues
adjust_security_modules

# Create required directories if they do not exist
echo "Ensuring application directories exist..."
mkdir -p "$APP_DIR" "$TEMPLATES_DIR" || handle_error "Failed to create application directories."

# Set ownership and permissions for the application directory
echo "Setting ownership and permissions for $APP_DIR..."
chown -R root:root "$APP_DIR" || handle_error "Failed to set ownership for $APP_DIR."
chmod -R 755 "$APP_DIR" || handle_error "Failed to set permissions for $APP_DIR."
echo "Ownership and permissions set."

# Function to backup a file if it exists
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

# Function to restore a file from backup if backup exists
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

# Backup current config files if they exist
backup_file "$CONFIG_FILE" "$CONFIG_BACKUP"
backup_file "$MAPPINGS_FILE" "$MAPPINGS_BACKUP"
backup_file "$DEVICES_FILE" "$DEVICES_BACKUP"

# Download and unzip the latest code from the repository
echo "Downloading latest code..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || handle_error "Repository download failed."

echo "Unzipping latest code..."
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || handle_error "Unzip failed."

# Restore configuration files after update
restore_file "$CONFIG_BACKUP" "$CONFIG_FILE"
restore_file "$MAPPINGS_BACKUP" "$MAPPINGS_FILE"
restore_file "$DEVICES_BACKUP" "$DEVICES_FILE"

# Move extracted files while excluding config.yaml, mappings.yaml, and devices.yaml
echo "Updating application files..."
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || handle_error "Move extracted files failed."

# Set appropriate permissions for all files in APP_DIR
echo "Setting permissions for application files..."
chmod -R u+rwX,go+rX "$APP_DIR" || handle_error "Failed to set permissions for application files."
echo "Permissions set."

# Set appropriate permissions for the self-update script
chmod +x "$APP_DIR/self-update.sh" || handle_error "Setting executable permission failed."

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"
echo "Temporary files cleaned."

# Function to determine if Docker Compose services are already running
services_running() {
  docker compose ps -q | grep -q .
}

# Navigate to the application directory
cd "$APP_DIR" || handle_error "Failed to navigate to $APP_DIR."

# Export to disable BuildKit
export DOCKER_BUILDKIT=0
echo "Docker BuildKit disabled."

# Rebuild Docker containers with the latest code
echo "Rebuilding Docker containers..."

if services_running; then
  echo "Existing Docker containers detected. Restarting containers..."
  docker compose down || handle_error "Docker Compose down failed."
else
  echo "No existing Docker containers detected. Starting containers..."
fi

docker compose up --build -d || handle_error "Docker Compose up failed."
echo "Docker containers rebuilt and started."

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

echo "Installation/Update applied successfully!"
