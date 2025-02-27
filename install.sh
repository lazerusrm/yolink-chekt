#!/bin/bash

# Ensure the script is run with bash
if [ -z "$BASH_VERSION" ]; then
  echo "Please run this script with bash."
  exit 1
fi

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo."
  exit 1
fi

# Define variables with defaults
REPO_URL="${REPO_URL:-https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip}"
APP_DIR="${APP_DIR:-/opt/yolink-chekt}"
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_VERSION:-v2.29.5}"

LOG_FILE="/var/log/yolink-installer.log"
exec > >(tee -i "$LOG_FILE")
exec 2>&1

echo "Starting YoLink CHEKT Installer at $(date)"

# Update package list
apt-get update || { echo "apt-get update failed."; exit 1; }

# Install required dependencies
echo "Installing required dependencies..."
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip software-properties-common rsync jq || { echo "Dependency installation failed."; exit 1; }

# Install Docker if not already installed
if ! [ -x "$(command -v docker)" ]; then
  echo "Docker not found, installing Docker..."
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg || { echo "Adding Docker GPG key failed."; exit 1; }
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null || { echo "Adding Docker repository failed."; exit 1; }
  apt-get update || { echo "apt-get update failed."; exit 1; }
  apt-get install -y docker-ce docker-ce-cli containerd.io || { echo "Docker installation failed."; exit 1; }
else
  echo "Docker is already installed."
fi

# Verify Docker installation
if ! [ -x "$(command -v docker)" ]; then
  echo "Docker installation failed. Exiting."
  exit 1
else
  echo "Docker is installed successfully."
fi

# Install Docker Compose plugin if not already installed
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose not found, installing Docker Compose plugin..."
  apt-get install -y docker-compose-plugin || { echo "Docker Compose plugin installation failed."; exit 1; }
else
  echo "Docker Compose is already installed."
fi

# Verify Docker Compose installation
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose installation failed. Exiting."
  exit 1
else
  echo "Docker Compose is installed successfully."
fi

# Download the repository as a ZIP file and extract it
echo "Downloading repository from $REPO_URL..."
mkdir -p "$APP_DIR"
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || { echo "Repository download failed."; exit 1; }
unzip "$APP_DIR/repo.zip" -d "$APP_DIR" || { echo "Unzip failed."; exit 1; }

# Ensure templates and logs directories exist and copy templates
echo "Copying new template files..."
mkdir -p "$APP_DIR/templates/"
mkdir -p "$APP_DIR/logs/"
rsync -a "$APP_DIR/yolink-chekt-main/templates/" "$APP_DIR/templates/" || { echo "Failed to copy templates."; exit 1; }

# Move extracted files and clean up
rsync -a "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || { echo "Move extracted files failed."; exit 1; }
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"

# Create default configuration files if they don't exist
if [ ! -f "$APP_DIR/config.yaml" ]; then
cat <<EOT > "$APP_DIR/config.yaml"
yolink:
  url: "https://api.yosmart.com"
  csid: "your_csid"
  csseckey: "your_csseckey"
  token: ""
chekt:
  api_token: ""
mqtt:
  url: "mqtt://api.yosmart.com"
  port: 8003
  topic: "yl-home/\${Home ID}/+/report"
  username: ""
  password: ""
mqtt_monitor:
  url: "mqtt://monitor.industrialcamera.com"
  port: 1883
  username: ""
  password: ""
receiver_type: "CHEKT"
sia:
  ip: ""
  port: ""
  account_id: ""
  transmitter_id: ""
  contact_id: ""
  encryption_key: ""
monitor:
  api_key: ""
timezone: "UTC"
users: {}
EOT
fi

if [ ! -f "$APP_DIR/devices.yaml" ]; then
cat <<EOT > "$APP_DIR/devices.yaml"
devices: []
EOT
fi

if [ ! -f "$APP_DIR/mappings.yaml" ]; then
cat <<EOT > "$APP_DIR/mappings.yaml"
mappings: []
EOT
fi

# Navigate to the app directory
cd "$APP_DIR" || { echo "Failed to navigate to app directory."; exit 1; }

# Build and run the app using Docker Compose
echo "Building and running the Docker containers..."
docker compose up --build -d || { echo "Docker Compose up failed."; exit 1; }

# Verify Docker containers are running
if ! docker compose ps | grep -q "Up"; then
  echo "Docker containers are not running as expected."; exit 1;
else
  echo "Docker containers are running successfully."
fi

# Create a self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"

echo "Creating self-update script..."
bash -c "cat <<EOT > $SELF_UPDATE_SCRIPT
#!/bin/bash
REPO_URL='https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip'
APP_DIR='/opt/yolink-chekt'
CONFIG_FILE=\"\$APP_DIR/config.yaml\"
CONFIG_BACKUP=\"\$APP_DIR/config.yaml.bak\"
MAPPINGS_FILE=\"\$APP_DIR/mappings.yaml\"
MAPPINGS_BACKUP=\"\$APP_DIR/mappings.yaml.bak\"
DEVICES_FILE=\"\$APP_DIR/devices.yaml\"
DEVICES_BACKUP=\"\$APP_DIR/devices.yaml.bak\"
LOG_FILE=\"/var/log/yolink-update.log\"

exec > >(tee -i \"\$LOG_FILE\")
exec 2>&1

if [ \"\$EUID\" -ne 0 ]; then
  echo \"This script must be run as root.\"
  exit 1
fi

backup_file() {
  local FILE=\"\$1\"
  local BACKUP=\"\$2\"
  if [ -f \"\$FILE\" ]; then
    cp \"\$FILE\" \"\$BACKUP\" || { echo \"Failed to backup \$(basename \"\$FILE\")\"; exit 1; }
  fi
}

restore_file() {
  local BACKUP=\"\$1\"
  local FILE=\"\$2\"
  if [ -f \"\$BACKUP\" ]; then
    mv \"\$BACKUP\" \"\$FILE\" || { echo \"Failed to restore \$(basename \"\$FILE\")\"; exit 1; }
  fi
}

cd \"\$APP_DIR\" || { echo 'Failed to navigate to app directory.'; exit 1; }
backup_file \"\$CONFIG_FILE\" \"\$CONFIG_BACKUP\"
backup_file \"\$MAPPINGS_FILE\" \"\$MAPPINGS_BACKUP\"
backup_file \"\$DEVICES_FILE\" \"\$DEVICES_BACKUP\"
curl -L \"\$REPO_URL\" -o \"\$APP_DIR/repo.zip\" || { echo 'Repository download failed.'; exit 1; }
unzip -o \"\$APP_DIR/repo.zip\" -d \"\$APP_DIR\" || { echo 'Unzip failed.'; exit 1; }
rsync -a --exclude='config.yaml' --exclude='mappings.yaml' --exclude='devices.yaml' \"\$APP_DIR/yolink-chekt-main/\" \"\$APP_DIR/\" || { echo 'Move extracted files failed.'; exit 1; }
restore_file \"\$CONFIG_BACKUP\" \"\$CONFIG_FILE\"
restore_file \"\$MAPPINGS_BACKUP\" \"\$MAPPINGS_FILE\"
restore_file \"\$DEVICES_BACKUP\" \"\$DEVICES_FILE\"
rm -rf \"\$APP_DIR/yolink-chekt-main\"
rm \"\$APP_DIR/repo.zip\"
chmod -R u+rwX,go+rX \"\$APP_DIR\"
chmod +x \"\$APP_DIR/self-update.sh\"
docker compose down || { echo 'Docker Compose down failed.'; exit 1; }
docker compose up --build -d || { echo 'Docker Compose up failed.'; exit 1; }
echo 'Updates applied successfully!'
EOT"

# Make the self-update script executable
chmod +x "$SELF_UPDATE_SCRIPT"

# Set up a cron job to run the self-update script daily at 2 AM
if command -v crontab >/dev/null 2>&1; then
  (crontab -l 2>/dev/null; echo "0 2 * * * $SELF_UPDATE_SCRIPT >> /var/log/yolink-update.log 2>&1") | crontab - || { echo "Cron job setup failed."; exit 1; }
else
  echo "Cron not available; manual updates required."
fi

echo "The YoLink CHEKT integration is now running and automatic updates are configured."