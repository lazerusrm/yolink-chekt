#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"

# Update package list
apt-get update || { echo "apt-get update failed."; exit 1; }

# Check if Docker is installed, install if necessary
if ! [ -x "$(command -v docker)" ]; then
  echo "Docker not found, installing..."
  apt-get install -y ca-certificates curl gnupg lsb-release || { echo "Dependency installation for Docker failed."; exit 1; }
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update || { echo "apt-get update failed."; exit 1; }
  apt-get install -y docker-ce docker-ce-cli containerd.io || { echo "Docker installation failed."; exit 1; }
fi

# Check if Docker Compose is installed, install if necessary
if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Docker Compose not found, installing..."
  apt-get install -y curl || { echo "Curl installation failed."; exit 1; }
  curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose || { echo "Docker Compose installation failed."; exit 1; }
fi

# Check if unzip is installed, install if necessary
if ! [ -x "$(command -v unzip)" ]; then
  echo "Unzip not found, installing..."
  apt-get install -y unzip || { echo "Unzip installation failed."; exit 1; }
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
cd "$APP_DIR"

# Build and run the app using Docker Compose
echo "Building and running the Docker containers..."
docker-compose up --build -d || { echo "Docker Compose up failed."; exit 1; }

# Optional: Set up the app to run as a service
echo "Setting up the app to run as a service..."

SERVICE_FILE="/etc/systemd/system/yolink-chekt.service"

bash -c "cat <<EOT > $SERVICE_FILE
[Unit]
Description=Yolink CHEKT Integration Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/docker-compose up --build
ExecStop=/usr/local/bin/docker-compose down
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOT"

# Reload systemd and enable the service
systemctl daemon-reload || { echo "Systemd daemon-reload failed."; exit 1; }
systemctl enable yolink-chekt || { echo "Systemd enable service failed."; exit 1; }
systemctl start yolink-chekt || { echo "Systemd start service failed."; exit 1; }

# Create the self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"

bash -c "cat <<EOT > $SELF_UPDATE_SCRIPT
#!/bin/bash

# Define variables
REPO_URL='https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip'
APP_DIR='/opt/yolink-chekt'

# Navigate to the app directory
cd \"\$APP_DIR\"

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

# Set up a cron job to run the self-update script daily at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * $SELF_UPDATE_SCRIPT >> /var/log/yolink-update.log 2>&1") | crontab -

echo "The Yolink CHEKT integration service is now running, and automatic updates have been configured."