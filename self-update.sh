#!/bin/bash

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt.git"
APP_DIR="/opt/yolink-chekt"

# Navigate to the app directory
cd "$APP_DIR"

# Fetch the latest changes from the GitHub repository
echo "Checking for updates from $REPO_URL..."
git fetch

# Check if there are any new changes
if [ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]; then
    echo "New updates found! Pulling the latest changes..."
    
    # Pull the latest changes
    git pull origin main
    
    # Rebuild the Docker containers with the latest code
    echo "Rebuilding Docker containers..."
    docker-compose down
    docker-compose up --build -d
    
    echo "Updates applied successfully!"
else
    echo "No updates found. Everything is up-to-date."
fi
