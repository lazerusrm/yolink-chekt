#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"

# Update package list
apt-get update || { echo "apt-get update failed."; exit 1; }

# Install dependencies needed for Docker Compose and unzip
apt-get install -y apt-transport-https ca-certificates curl gnupg unzip || { echo "Dependency installation failed."; exit 1; }

# Check if Docker Compose is installed, install if necessary
if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Docker Compose not found, installing..."
  curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose || { echo "Docker Compose installation failed."; exit 1; }
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
docker-compose up --build -d || { echo "Docker Compose up failed."; exit 1; }

# Verify Docker containers are running
if ! docker-compose ps | grep -q "Up"; then
  echo "Docker containers are not running as expected."; exit 1;
fi

# Optional: Create a self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"

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
docker-compose down || { echo 'Docker Compose down failed.'; exit 1; }
docker-compose up --build -d || { echo 'Docker Compose up failed.'; exit 1; }

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
