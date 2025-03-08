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
LOG_FILE="/var/log/yolink-installer.log"

# Redirect output to log file
exec > >(tee -i "$LOG_FILE") 2>&1

echo "Starting YoLink CHEKT Installer at $(date)"

# Update package list
apt-get update || { echo "apt-get update failed."; exit 1; }

# Install required dependencies
echo "Installing required dependencies..."
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip software-properties-common rsync jq iproute2 || { echo "Dependency installation failed."; exit 1; }

# Install Docker if not already installed
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found, installing Docker..."
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg || { echo "Adding Docker GPG key failed."; exit 1; }
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources/list.d/docker.list > /dev/null || { echo "Adding Docker repository failed."; exit 1; }
    apt-get update || { echo "apt-get update failed."; exit 1; }
    apt-get install -y docker-ce docker-ce-cli containerd.io || { echo "Docker installation failed."; exit 1; }
else
    echo "Docker is already installed."
fi

# Verify Docker installation
if ! command -v docker >/dev/null 2>&1; then
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

# Create application directory
echo "Creating application directory at $APP_DIR..."
mkdir -p "$APP_DIR" || { echo "Failed to create $APP_DIR."; exit 1; }
mkdir -p "$APP_DIR/logs" "$APP_DIR/templates"

# Download and extract the repository
echo "Downloading repository from $REPO_URL..."
curl -L "$REPO_URL" -o "$APP_DIR/repo.zip" || { echo "Repository download failed."; exit 1; }
unzip "$APP_DIR/repo.zip" -d "$APP_DIR" || { echo "Unzip failed."; exit 1; }

# Move extracted files and clean up
rsync -a "$APP_DIR/yolink-chekt-main/" "$APP_DIR/" || { echo "Failed to move extracted files."; exit 1; }
rm -rf "$APP_DIR/yolink-chekt-main" "$APP_DIR/repo.zip"

# Create Dockerfile.modbus-proxy
echo "Creating Dockerfile.modbus-proxy..."
cat <<EOT > "$APP_DIR/Dockerfile.modbus-proxy"
FROM python:3.10-slim
WORKDIR /app
COPY modbus_proxy.py /app/
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 1502
CMD ["python", "modbus_proxy.py"]
EOT

# Set permissions
echo "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { echo "Failed to set directory permissions."; exit 1; }

# Navigate to the app directory
cd "$APP_DIR" || { echo "Failed to navigate to app directory."; exit 1; }

# Create initial .env file if it doesn’t exist
if [ ! -f "$APP_DIR/.env" ]; then
    echo "Creating default .env file..."
    cat <<EOT > "$APP_DIR/.env"
# RTSP Streamer Configuration
RTSP_PORT=554
RTSP_API_PORT=80
ONVIF_PORT=8000
STREAM_NAME=yolink-dashboard
FRAME_RATE=1
WIDTH=1920
HEIGHT=1080
CYCLE_INTERVAL=10000
ENABLE_ONVIF=true
DASHBOARD_URL=http://websocket-proxy:3000
SERVER_IP=auto
EOT
fi

# Function to get the IP address of the interface with the default route to the internet
get_host_ip() {
    HOST_IP=$(ip route get 8.8.8.8 | grep -o 'src [0-9.]*' | awk '{print $2}')
    if [ -z "$HOST_IP" ]; then
        echo "Error: Could not determine IP address with internet route."
        exit 1
    fi
    echo "Detected host IP with internet route: $HOST_IP"
    echo "$HOST_IP"
}

# Update docker-compose.yml with host IP
update_docker_compose_ip() {
    local host_ip="$1"
    local DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"
    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        echo "Error: docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
        exit 1
    }

    if grep -q "TARGET_IP=" "$DOCKER_COMPOSE_FILE"; then
        sed -i "/modbus-proxy:/,/^[^ ]/ s/TARGET_IP=.*/TARGET_IP=$host_ip/" "$DOCKER_COMPOSE_FILE" || {
            echo "Error: Failed to update TARGET_IP in docker-compose.yml"
            exit 1
        }
    else
        sed -i "/modbus-proxy:/,/environment:/ { /environment:/ a\      - TARGET_IP=$host_ip" "$DOCKER_COMPOSE_FILE" || {
            echo "Error: Failed to append TARGET_IP to docker-compose.yml"
            exit 1
        }
    fi
    echo "Updated docker-compose.yml with TARGET_IP=$host_ip"
}

# Update docker-compose.yml with the host IP
HOST_IP=$(get_host_ip)
update_docker_compose_ip "$HOST_IP"

# Build and run the app using Docker Compose
echo "Building and running the Docker containers..."
docker compose up --build -d || { echo "Docker Compose up failed."; exit 1; }

# Verify Docker containers are running
if ! docker compose ps | grep -q "Up"; then
    echo "Docker containers are not running as expected."
    exit 1
else
    echo "Docker containers are running successfully."
fi

# Create a self-update script
SELF_UPDATE_SCRIPT="$APP_DIR/self-update.sh"
echo "Creating self-update script..."
cat <<'EOT' > "$SELF_UPDATE_SCRIPT"
#!/bin/bash
set -e
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

mkdir -p "$LOG_DIR" || { echo "Failed to create log directory $LOG_DIR"; exit 1; }
chmod 755 "$LOG_DIR"
if ! exec > >(tee -a "$LOG_FILE") 2>&1; then
    LOG_FILE="/tmp/yolink-update.log"
    echo "Warning: Could not write to $LOG_FILE, falling back to $LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

if [ "$EUID" -ne 0 ]; then
    log "Error: This script must be run as root."
    exit 1
fi

get_host_ip() {
    HOST_IP=$(ip route get 8.8.8.8 | grep -o 'src [0-9.]*' | awk '{print $2}')
    if [ -z "$HOST_IP" ]; then
        log "Error: Could not determine IP address with internet route."
        exit 1
    fi
    log "Detected host IP with internet route: $HOST_IP"
    echo "$HOST_IP"
}

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

update_docker_compose_ip() {
    local host_ip="$1"
    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        log "Error: docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
        exit 1
    }
    if grep -q "TARGET_IP=" "$DOCKER_COMPOSE_FILE"; then
        sed -i "/modbus-proxy:/,/^[^ ]/ s/TARGET_IP=.*/TARGET_IP=$host_ip/" "$DOCKER_COMPOSE_FILE" || {
            log "Error: Failed to update TARGET_IP in docker-compose.yml"
            exit 1
        }
    else
        sed -i "/modbus-proxy:/,/environment:/ { /environment:/ a\      - TARGET_IP=$host_ip" "$DOCKER_COMPOSE_FILE" || {
            log "Error: Failed to append TARGET_IP to docker-compose.yml"
            exit 1
        }
    fi
    log "Updated docker-compose.yml with TARGET_IP=$host_ip"
}

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
            local curl_err=$(cat /tmp/curl_error)
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

log "Starting update process in $APP_DIR"
cd "$APP_DIR" || { log "Error: Cannot access $APP_DIR"; exit 1; }
backup_file "$ENV_FILE" "$ENV_BACKUP"
if [ -d "$APP_DIR/rtsp-streamer" ]; then
    log "Backing up rtsp-streamer directory"
    rm -rf "$APP_DIR/rtsp-streamer.bak"
    cp -r "$APP_DIR/rtsp-streamer" "$APP_DIR/rtsp-streamer.bak" || { log "Error: Failed to backup rtsp-streamer"; exit 1; }
fi
download_with_retry "$REPO_URL" "$APP_DIR/repo.zip"
log "Extracting repository..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR" || { log "Error: Failed to create temp directory"; exit 1; }
unzip -o "$APP_DIR/repo.zip" -d "$TEMP_DIR" || { log "Error: Failed to unzip repository"; exit 1; }
log "Updating application files..."
rsync -a --exclude='.env' "$TEMP_DIR/yolink-chekt-main/"* "$APP_DIR/" || { log "Error: Failed to sync updated files"; exit 1; }
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
restore_file "$ENV_BACKUP" "$ENV_FILE"
log "Cleaning up..."
rm -rf "$TEMP_DIR" "$APP_DIR/repo.zip" "$APP_DIR/rtsp-streamer.bak" /tmp/curl_error || log "Warning: Some cleanup tasks failed"
log "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { log "Error: Failed to set directory permissions"; exit 1; }
chmod +x "$APP_DIR/self-update.sh" || { log "Error: Failed to set script permissions"; exit 1; }
HOST_IP=$(get_host_ip)
update_docker_compose_ip "$HOST_IP"
log "Rebuilding and restarting Docker containers..."
docker compose down || { log "Error: Failed to stop Docker containers"; exit 1; }
docker compose up --build -d || { log "Error: Failed to start Docker containers"; exit 1; }
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
rtsp_container=$(docker ps --filter "name=yolink-rtsp-streamer" --format '{{.Names}}' | head -n 1)
if [ -n "$rtsp_container" ]; then
    log "Verified: RTSP streamer container is running"
else
    log "Warning: RTSP streamer container not running; check logs"
fi
log "Update completed successfully!"
EOT

chmod +x "$SELF_UPDATE_SCRIPT"

# Set up a cron job to run the self-update script daily at 2 AM
if command -v crontab >/dev/null 2>&1; then
    (crontab -l 2>/dev/null | grep -v "$SELF_UPDATE_SCRIPT"; echo "0 2 * * * $SELF_UPDATE_SCRIPT >> /var/log/yolink-update.log 2>&1") | crontab - || { echo "Cron job setup failed."; exit 1; }
    echo "Cron job set up to run self-update daily at 2 AM."
else
    echo "Cron not available; manual updates required."
fi

echo "The YoLink CHEKT integration is now installed and automatic updates are configured."