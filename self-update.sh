#!/bin/bash

# Transition self-update.sh script for YoLink CHEKT Integration
# This script helps migrate existing installations to the new unified script approach

APP_DIR="/opt/yolink-chekt"
LOG_FILE="/var/log/yolink-update.log"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Redirect output to log file with timestamp
exec > >(tee -a >(while read line; do echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line"; done >> "$LOG_FILE")) 2>&1

echo "Starting self-update.sh (transition version)"

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Check if install.sh exists
if [ ! -f "$APP_DIR/install.sh" ]; then
    echo "Error: New install.sh script not found. Running legacy update process."

    # If we're here, we need to run the legacy update process
    # This would be the original self-update.sh content, but for brevity
    # we'll just exit with an error since we're expecting the new install.sh to exist
    echo "Legacy update process is no longer supported. Please install the new version."
    exit 1
fi

# Ensure install.sh is executable
if [ ! -x "$APP_DIR/install.sh" ]; then
    echo "Setting executable permissions on install.sh"
    chmod +x "$APP_DIR/install.sh"
fi

# Check if cron already updated
CRON_UPDATED_FILE="$APP_DIR/.cron_updated"
if [ ! -f "$CRON_UPDATED_FILE" ]; then
    echo "Updating cron job to use the new unified script..."

    # Get the current crontab
    TMPFILE=$(mktemp)
    crontab -l > "$TMPFILE" 2>/dev/null

    # Replace the self-update.sh reference with install.sh --update
    sed -i "s|$APP_DIR/self-update.sh|$APP_DIR/install.sh --update|g" "$TMPFILE"

    # Apply the updated crontab
    crontab "$TMPFILE"
    rm -f "$TMPFILE"

    # Mark that the cron has been updated
    touch "$CRON_UPDATED_FILE"

    echo "Cron job updated successfully."
fi

# Execute the new unified script with update flag
echo "Forwarding to new unified script (install.sh --update)..."
cd "$APP_DIR" # Change to the app directory to ensure any relative paths work
exec "$APP_DIR/install.sh" --update