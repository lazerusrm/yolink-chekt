#!/bin/bash

# Exit on any error
set -e

# Define variables
REPO_URL="https://github.com/lazerusrm/yolink-chekt/archive/refs/heads/main.zip"
APP_DIR="/opt/yolink-chekt"
ENV_FILE="$APP_DIR/.env"
ENV_BACKUP="$APP_DIR/.env.bak"
LOG_DIR="/var/log"
LOG_FILE="$LOG_DIR/yolink-update.log"
MAX_RETRIES=3
RETRY_DELAY=5
TEMP_DIR="$APP_DIR/temp-update"
DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"

# Ensure log directory exists
mkdir -p "$LOG_DIR" || { echo "Failed to create log directory $LOG_DIR"; exit 1; }
chmod 755 "$LOG_DIR"

# Redirect output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Timestamped log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    log "Error: This script must be run as root."
    exit 1
fi

# Function to get the IP address silently (no logging during capture)
get_host_ip_silent() {
    ip route get 8.8.8.8 | grep -o 'src [0-9.]*' | awk '{print $2}'
}

# Function to get the IP address with logging
get_host_ip() {
    # First capture the IP silently
    local host_ip
    host_ip=$(get_host_ip_silent)

    # Only log after we've captured the IP
    if [ -z "$host_ip" ]; then
        log "Error: Could not determine IP address with internet route."
        exit 1
    fi
    log "Detected host IP with internet route: $host_ip"
    echo "$host_ip"
}

# Backup a file if it exists
backup_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        cp "$src" "$dest" || { log "Error: Failed to backup $(basename "$src")"; exit 1; }
        log "Backed up $(basename "$src") to $(basename "$dest")"
    else
        log "Note: $(basename "$src") not found, skipping backup"
    fi
}

# Restore a file if backup exists
restore_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        mv "$src" "$dest" || { log "Error: Failed to restore $(basename "$dest")"; exit 1; }
        log "Restored $(basename "$dest") from backup"
    else
        log "Note: Backup $(basename "$src") not found, skipping restore"
    fi
}

# Update docker-compose.yml with host IP - properly handles YAML formatting
update_docker_compose_ip() {
    # IMPORTANT: Capture host IP directly in a variable, don't use command substitution with logs
    local host_ip
    host_ip=$(get_host_ip_silent)

    # Now log after capturing the IP
    log "Updating docker-compose.yml with TARGET_IP=$host_ip"

    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        log "Error: docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
        exit 1
    fi

    # Make a backup
    cp "$DOCKER_COMPOSE_FILE" "${DOCKER_COMPOSE_FILE}.bak" || {
        log "Error: Failed to create backup of docker-compose.yml"
        exit 1
    }

    # Create a temporary file
    local tmpfile
    tmpfile=$(mktemp)

    # Process the file line by line, only updating the TARGET_IP line
    while IFS= read -r line; do
        if echo "$line" | grep -q "TARGET_IP="; then
            # Extract the indentation
            local indent
            indent=$(echo "$line" | sed -E 's/^([[:space:]]*-).*/\1/')
            echo "${indent} TARGET_IP=$host_ip" >> "$tmpfile"
        else
            echo "$line" >> "$tmpfile"
        fi
    done < "$DOCKER_COMPOSE_FILE"

    # Replace original file
    mv "$tmpfile" "$DOCKER_COMPOSE_FILE" || {
        log "Error: Failed to update docker-compose.yml"
        mv "${DOCKER_COMPOSE_FILE}.bak" "$DOCKER_COMPOSE_FILE"
        rm -f "$tmpfile"
        exit 1
    }

    # Ensure volumes section is complete and properly formatted
    if grep -q "^volumes:$" "$DOCKER_COMPOSE_FILE"; then
        # Check if redis-data is already defined
        if ! grep -q "redis-data:" "$DOCKER_COMPOSE_FILE"; then
            # Create a temporary file
            local vol_tmpfile
            vol_tmpfile=$(mktemp)

            # Process the file, adding proper volumes mapping
            awk '{
                print $0;
                if ($0 ~ /^volumes:$/) {
                    print "  redis-data: {}";
                }
            }' "$DOCKER_COMPOSE_FILE" > "$vol_tmpfile"

            # Replace the original file
            mv "$vol_tmpfile" "$DOCKER_COMPOSE_FILE" || {
                log "Error: Failed to update volumes in docker-compose.yml"
                exit 1;
            }

            log "Fixed volumes section in docker-compose.yml with proper mapping"
        fi
    fi

    log "Successfully updated docker-compose.yml"
}

# Download with retry logic
download_with_retry() {
    local url="$1"
    local output="$2"
    local attempt=1
    while [ "$attempt" -le "$MAX_RETRIES" ]; do
        log "Downloading from $url (Attempt $attempt/$MAX_RETRIES)..."
        if curl -L --fail "$url" -o "$output" 2>/tmp/curl_error; then
            log "Download successful"
            return 0
        else
            local curl_err
            curl_err=$(cat /tmp/curl_error)
            log "Download failed: $curl_err"
            if [ "$attempt" -eq "$MAX_RETRIES" ]; then
                log "Error: Failed to download repository after $MAX_RETRIES attempts"
                exit 1
            fi
            sleep "$RETRY_DELAY"
            ((attempt++))
        fi
    done
}

# Start update process
log "Starting update process in $APP_DIR"
cd "$APP_DIR" || { log "Error: Cannot access $APP_DIR"; exit 1; }

# Backup existing .env file
backup_file "$ENV_FILE" "$ENV_BACKUP"

# Backup rtsp-streamer directory
if [ -d "$APP_DIR/rtsp-streamer" ]; then
    log "Backing up rtsp-streamer directory"
    rm -rf "$APP_DIR/rtsp-streamer.bak"
    cp -r "$APP_DIR/rtsp-streamer" "$APP_DIR/rtsp-streamer.bak" || { log "Error: Failed to backup rtsp-streamer"; exit 1; }
fi

# Download and extract repository
download_with_retry "$REPO_URL" "$APP_DIR/repo.zip"
log "Extracting repository..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR" || { log "Error: Failed to create temp directory"; exit 1; }
unzip -o "$APP_DIR/repo.zip" -d "$TEMP_DIR" || { log "Error: Failed to unzip repository"; exit 1; }

# Update files, excluding .env and docker-compose.yml (to preserve customizations)
log "Updating application files..."
rsync -a --exclude='.env' --exclude='docker-compose.yml' "$TEMP_DIR/yolink-chekt-main/"* "$APP_DIR/" || { log "Error: Failed to sync updated files"; exit 1; }

# Ensure rtsp-streamer directory is updated
if [ -d "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" ]; then
    log "Updating rtsp-streamer directory..."
    rm -rf "$APP_DIR/rtsp-streamer"
    cp -r "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" "$APP_DIR/" || { log "Error: Failed to update rtsp-streamer"; exit 1; }
elif [ -d "$APP_DIR/rtsp-streamer.bak" ]; then
    log "Restoring rtsp-streamer from backup"
    cp -r "$APP_DIR/rtsp-streamer.bak" "$APP_DIR/rtsp-streamer" || { log "Error: Failed to restore rtsp-streamer"; exit 1; }
else
    log "Warning: No rtsp-streamer in repo or backup; it will be missing"
fi

# Restore .env file
restore_file "$ENV_BACKUP" "$ENV_FILE"

# Clean up temporary files
log "Cleaning up..."
rm -rf "$TEMP_DIR" "$APP_DIR/repo.zip" "$APP_DIR/rtsp-streamer.bak" /tmp/curl_error || log "Warning: Some cleanup tasks failed"

# Set permissions
log "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { log "Error: Failed to set directory permissions"; exit 1; }
chmod +x "$APP_DIR/self-update.sh" || { log "Error: Failed to set script permissions"; exit 1; }

# Update docker-compose.yml with the host IP
update_docker_compose_ip

# Determine which Docker Compose command to use
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif docker-compose --version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    log "Error: No Docker Compose command available. Please install Docker Compose."
    exit 1
fi

# Rebuild and restart Docker containers
log "Rebuilding and restarting Docker containers..."
$DOCKER_COMPOSE_CMD down || { log "Error: Failed to stop Docker containers"; exit 1; }
$DOCKER_COMPOSE_CMD up --build -d || { log "Error: Failed to start Docker containers"; exit 1; }

# Verify main container
container_name=$(docker ps --filter "name=yolink_chekt" --format '{{.Names}}' | head -n 1)
if [ -z "$container_name" ]; then
    log "Error: Main yolink_chekt container not found"
    exit 1
fi
if docker exec "$container_name" test -f "/app/templates/config.html"; then
    log "Verified: config.html present in container"
else
    log "Error: config.html not found in container"
    exit 1
fi

# Verify rtsp-streamer container
rtsp_container=$(docker ps --filter "name=yolink-rtsp-streamer" --format '{{.Names}}' | head -n 1)
if [ -n "$rtsp_container" ]; then
    log "Verified: RTSP streamer container is running"
else
    log "Warning: RTSP streamer container not running; check logs"
fi

log "Update completed successfully!"