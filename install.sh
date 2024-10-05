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
  curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
fi

# Clone the repository
echo "Cloning repository from $REPO_URL..."
git clone "$REPO_URL" "$APP_DIR"

# Navigate to the app directory
cd "$APP_DIR"

# Build and run the app using Docker Compose
echo "Building and running the Docker containers..."
docker-compose up --build -d

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
systemctl daemon-reload
systemctl enable yolink-chekt
systemctl start yolink-chekt

# Create the self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"

bash -c "cat <<EOT > $SELF_UPDATE_SCRIPT
#!/bin/bash

# Define variables
REPO_URL='https://github.com/lazerusrm/yolink-chekt.git'
APP_DIR='/opt/yolink-chekt'

# Navigate to the app directory
cd \"\$APP_DIR\"

# Fetch the latest changes from the GitHub repository
echo 'Checking for updates from \$REPO_URL...'
git fetch

# Check if there are any new changes
if [ \$(git rev-parse HEAD) != \$(git rev-parse @{u}) ]; then
    echo 'New updates found! Pulling the latest changes...'
    
    # Pull the latest changes
    git pull origin main
    
    # Rebuild the Docker containers with the latest code
    echo 'Rebuilding Docker containers...'
    docker-compose down
    docker-compose up --build -d
    
    echo 'Updates applied successfully!'
else
    echo 'No updates found. Everything is up-to-date.'
fi
EOT"

# Make the self-update script executable
chmod +x "$SELF_UPDATE_SCRIPT"

# Set up a cron job to run the self-update script daily at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * $SELF_UPDATE_SCRIPT >> /var/log/yolink-update.log 2>&1") | crontab -

echo "The Yolink CHEKT integration service is now running, and automatic updates have been configured."
