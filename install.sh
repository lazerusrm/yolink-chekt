#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"
DOCKER_COMPOSE_VERSION="v2.29.5"

# Update package list
apt-get update || { echo "apt-get update failed."; exit 1; }

# Install required dependencies
echo "Installing required dependencies..."
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip software-properties-common || { echo "Dependency installation failed."; exit 1; }

# Install Docker if not already installed
if ! [ -x "$(command -v docker)" ]; then
  echo "Docker not found, installing Docker..."

  # Add Docker's official GPG key
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg || { echo "Adding Docker GPG key failed."; exit 1; }

  # Set up the stable Docker repository
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null || { echo "Adding Docker repository failed."; exit 1; }

  # Update package list and install Docker Engine
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

# Install Docker Compose if not already installed
if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Docker Compose not found, installing Docker Compose plugin..."

  # Install Docker Compose using the Docker plugin
  apt-get install -y docker-compose-plugin || { echo "Docker Compose plugin installation failed."; exit 1; }

  # Remove any incorrect old Docker Compose binary
  if [ -f /usr/local/bin/docker-compose ]; then
    echo "Removing old Docker Compose binary..."
    rm /usr/local/bin/docker-compose || { echo "Failed to remove old Docker Compose binary."; exit 1; }
  fi
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
mv "$APP_DIR/yolink-chekt-main/"* "$APP_DIR/" || { echo "Move extracted files failed."; exit 1; }
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"

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

# Optional: Create a self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"

echo "Creating self-update script..."
bash -c "cat <<EOT > $SELF_UPDATE_SCRIPT
#!/bin/bash

# Define variables
REPO_URL='https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip'
APP_DIR='/opt/yolink-chekt'

# Navigate to the app directory
cd \"\$APP_DIR\" || { echo 'Failed to navigate to app directory.'; exit 1; }

# Download the latest changes as a ZIP file
echo 'Checking for updates from \$REPO_URL...'
curl -L \"\$REPO_URL\" -o \"\$APP_DIR/repo.zip\" || { echo 'Repository download failed.'; exit 1; }
unzip -o \"\$APP_DIR/repo.zip\" -d \"\$APP_DIR\" || { echo 'Unzip failed.'; exit 1; }
mv \"\$APP_DIR/yolink-chekt-main/\"* \"\$APP_DIR/\" || { echo 'Move extracted files failed.'; exit 1; }
rm -rf \"\$APP_DIR/yolink-chekt-main\"
rm \"\$APP_DIR/repo.zip\"

# Rebuild the Docker containers with the latest code
echo 'Rebuilding Docker containers...'
docker compose down || { echo 'Docker Compose down failed.'; exit 1; }
docker compose up --build -d || { echo 'Docker Compose up failed.'; exit 1; }

echo 'Updates applied successfully!'
EOT"

# Make the self-update script executable
chmod +x "$SELF_UPDATE_SCRIPT"

# Set up a cron job to run the self-update script daily at 2 AM (if cron is available in container)
if command -v crontab >/dev/null 2>&1; then
  (crontab -l 2>/dev/null; echo "0 2 * * * $SELF_UPDATE_SCRIPT >> /var/log/yolink-update.log 2>&1") | crontab - || { echo "Cron job setup failed."; exit 1; }
else
  echo "Cron not available in the container."
fi

echo "The Yolink CHEKT integration is now running and automatic updates are configured."
