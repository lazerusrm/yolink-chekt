#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"

# Navigate to the app directory
cd "$APP_DIR" || { echo 'Failed to navigate to app directory.'; exit 1; }

# Download the latest changes as a ZIP file
echo "Checking for updates from $REPO_URL..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || { echo 'Repository download failed.'; exit 1; }
unzip -o "$APP_DIR/repo.zip" -d "$APP_DIR" || { echo 'Unzip failed.'; exit 1; }

# Move extracted files while preserving the existing structure and keeping config.yaml intact
if ! command -v rsync &> /dev/null; then
  echo 'rsync not found. Please install rsync.'
  exit 1
fi
rsync -a --exclude='config.yaml' "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || { echo 'Move extracted files failed.'; exit 1; }
chmod +x "$APP_DIR/self-update.sh" || { echo 'Setting executable permission failed.'; exit 1; }
rm -rf "$APP_DIR/yolink-chekt-main"
rm "$APP_DIR/repo.zip"

# Rebuild the Docker containers with the latest code
echo "Rebuilding Docker containers..."
docker compose down || { echo 'Docker Compose down failed.'; exit 1; }
docker compose up --build -d || { echo 'Docker Compose up failed.'; exit 1; }

echo "Updates applied successfully!"
