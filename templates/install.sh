#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt.git"
APP_DIR="/opt/yolink-chekt"

# Check if Docker is installed, install if necessary
if ! [ -x "$(command -v docker)" ]; then
  echo "Docker not found, installing..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh
fi

# Check if Docker Compose is installed, install if necessary
if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Docker Compose not found, installing..."
  sudo curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
fi

# Clone the repository
echo "Cloning repository from $REPO_URL..."
git clone "$REPO_URL" "$APP_DIR"

# Navigate to the app directory
cd "$APP_DIR"

# Build and run the app using Docker Compose
echo "Building and running the Docker containers..."
sudo docker-compose up --build -d

# Optional: Set up the app as a service
echo "Setting up the app to run as a service..."

SERVICE_FILE="/etc/systemd/system/yolink-chekt.service"

sudo bash -c "cat <<EOT > $SERVICE_FILE
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
sudo systemctl daemon-reload
sudo systemctl enable yolink-chekt
sudo systemctl start yolink-chekt

echo "The Yolink CHEKT integration service is now running."
