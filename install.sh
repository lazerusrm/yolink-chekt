#!/bin/bash

# YoLink CHEKT Integration - Unified Installation and Update Script
# This script handles both first-time installation and updates with zero manual edits required

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
OPERATION_MODE="auto"
RTSP_HTTP_PORT=8080  # Use an alternative port for RTSP HTTP service to avoid conflict with nginx

# Process command-line arguments
for arg in "$@"; do
  case $arg in
    --install)
      OPERATION_MODE="install"
      shift
      ;;
    --update)
      OPERATION_MODE="update"
      shift
      ;;
    --help)
      echo "Usage: $0 [--install|--update|--help]"
      echo ""
      echo "Options:"
      echo "  --install  Force installation mode even if existing installation is detected"
      echo "  --update   Force update mode even if no existing installation is detected"
      echo "  --help     Show this help message"
      echo ""
      echo "Without options, the script will automatically detect whether to install or update."
      exit 0
      ;;
  esac
done

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Redirect output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check if this script is being executed as self-update.sh
SCRIPT_NAME=$(basename "$0")
if [ "$SCRIPT_NAME" = "self-update.sh" ]; then
    echo "Detected execution as self-update.sh, running in update mode."
    OPERATION_MODE="update"

    # Create a symlink to install.sh for future runs
    if [ ! -L "$APP_DIR/self-update.sh" ] && [ -f "$APP_DIR/install.sh" ]; then
        echo "Creating symbolic link from self-update.sh to install.sh"
        ln -sf "$APP_DIR/install.sh" "$APP_DIR/self-update.sh"
    fi

    # Update cron job to use install.sh directly in future
    if command -v crontab >/dev/null 2>&1; then
        CRON_ENTRY="0 2 * * * $APP_DIR/install.sh --update >> /var/log/yolink-update.log 2>&1"
        CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
        if echo "$CURRENT_CRON" | grep -q "$APP_DIR/self-update.sh"; then
            echo "Updating cron job to use install.sh instead of self-update.sh"
            NEW_CRON=$(echo "$CURRENT_CRON" | sed "s|$APP_DIR/self-update.sh|$APP_DIR/install.sh --update|g")
            echo "$NEW_CRON" | crontab -
        fi
    fi
fi

# Auto-detect operation mode if not specified
if [ "$OPERATION_MODE" = "auto" ]; then
    if [ -d "$APP_DIR" ] && [ -f "$APP_DIR/current_ip.txt" ]; then
        OPERATION_MODE="update"
        echo "Detected existing installation. Running in update mode."
    else
        OPERATION_MODE="install"
        echo "No existing installation detected. Running in install mode."
    fi
fi

echo "Starting YoLink CHEKT $OPERATION_MODE at $(date)"

# Common functions used in both installation and update

# Function to get the IP address silently (no logging during capture)
get_host_ip_silent() {
    ip route get 8.8.8.8 | grep -o 'src [0-9.]*' | awk '{print $2}'
}

# Function to get the IP address with logging
get_host_ip() {
    local HOST_IP
    HOST_IP=$(get_host_ip_silent)
    if [ -z "$HOST_IP" ]; then
        echo "Error: Could not determine IP address with internet route."
        exit 1
    fi
    echo "Detected host IP with internet route: $HOST_IP"
    echo "$HOST_IP"
}

# Function to check if IP has changed
check_ip_changed() {
    local current_ip=$(get_host_ip_silent)
    local stored_ip=""

    if [ -f "$APP_DIR/current_ip.txt" ]; then
        stored_ip=$(cat "$APP_DIR/current_ip.txt")
    fi

    if [ "$current_ip" != "$stored_ip" ]; then
        echo "IP address changed from $stored_ip to $current_ip"
        return 0  # IP has changed
    else
        echo "IP address unchanged: $current_ip"
        return 1  # IP has not changed
    fi
}

# Generate SSL certificates with proper Subject Alternative Name (SAN)
generate_ssl_certificates() {
    local host_ip=$1
    local cert_dir=$2
    local cert_file="${cert_dir}/cert.pem"
    local key_file="${cert_dir}/key.pem"

    mkdir -p "$cert_dir"

    # Create a temporary OpenSSL configuration file
    local ssl_config=$(mktemp)
    cat > "$ssl_config" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = YoLink CHEKT Integration

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = $host_ip
EOF

    echo "Generating SSL certificates with IP $host_ip in SAN field..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$key_file" -out "$cert_file" \
        -config "$ssl_config"

    if [ $? -eq 0 ]; then
        echo "SSL certificates generated successfully with IP $host_ip in SAN field."
        # Verify the certificate
        echo "Certificate SAN field verification:"
        openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject Alternative Name"
    else
        echo "Failed to generate SSL certificates. Falling back to basic certificates..."
        openssl req -x509 -newkey rsa:2048 -keyout "$key_file" \
            -out "$cert_file" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=YoLink/CN=localhost"
    fi

    chmod 600 "$key_file" "$cert_file"
    rm -f "$ssl_config"
}

# Function to generate nginx.conf with the current IP
generate_nginx_conf() {
    local host_ip=$1
    local nginx_conf="$APP_DIR/nginx.conf"

    echo "Generating nginx.conf with IP $host_ip..."
    cat > "$nginx_conf" << EOF
server {
    listen 80;
    server_name localhost $host_ip;

    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name localhost $host_ip;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Improved SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

    # Add SSL session cache for better performance
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Main application
    location / {
        proxy_pass http://yolink_chekt:5000;

        # Standard proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Additional headers to help with redirection
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Server \$host;

        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Proxy RTSP HTTP API requests to port $RTSP_HTTP_PORT
    location /rtsp/ {
        proxy_pass http://rtsp-streamer:$RTSP_HTTP_PORT/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    echo "nginx.conf generated successfully."
}

# Generate docker-compose.yml with correct config
generate_docker_compose() {
    local host_ip=$1
    local rtsp_http_port=$2
    local docker_compose_file="$APP_DIR/docker-compose.yml"

    echo "Generating docker-compose.yml with IP $host_ip..."
    cat > "$docker_compose_file" << EOF
version: '3'

services:
  nginx:
    image: nginx:latest
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./certs:/etc/nginx/certs
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - yolink_chekt
    restart: unless-stopped
    networks:
      - yolink-network

  yolink_chekt:
    build: .
    expose:
      - "5000"
    volumes:
      - ./certs:/app/certs
      - .:/app
      - ./logs:/app/logs
      - ./templates:/app/templates
    environment:
      - FLASK_ENV=production
      - LOG_DIR=/app/logs
      - DISABLE_HTTPS=true  # Let Nginx handle SSL
    depends_on:
      - redis
      - modbus-proxy
    restart: unless-stopped
    networks:
      - yolink-network

  modbus-proxy:
    build:
      context: .
      dockerfile: Dockerfile.modbus-proxy
    container_name: modbus-proxy
    ports:
      - "1502:1502"
      - "5001:5000"
    environment:
      - TARGET_IP=$host_ip
      - TARGET_PORT=502
      - LISTEN_PORT=1502
      - API_PORT=5000
      - FLASK_SECRET_KEY=Skunkworks1!
    restart: unless-stopped
    networks:
      - yolink-network

  redis:
    image: redis:6
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - yolink-network

  websocket-proxy:
    build:
      context: .
      dockerfile: websocket-proxy/Dockerfile
    container_name: yolink-websocket-proxy
    restart: unless-stopped
    environment:
      - PORT=3000
      - API_URL=http://yolink_chekt:5000/get_sensor_data
      - FETCH_INTERVAL=5000
    ports:
      - "3010:3000"
    volumes:
      - ./certs:/app/certs
    depends_on:
      - yolink_chekt
    networks:
      - yolink-network

  rtsp-streamer:
    build:
      context: ./rtsp-streamer
      dockerfile: Dockerfile
    container_name: yolink-rtsp-streamer
    restart: unless-stopped
    environment:
      - DASHBOARD_URL=http://websocket-proxy:3000
      - RTSP_PORT=554
      - STREAM_NAME=yolink-dashboard
      - FRAME_RATE=6
      - WIDTH=1920
      - HEIGHT=1080
      - CYCLE_INTERVAL=10000
      - ONVIF_AUTH_REQUIRED=true
      - ONVIF_USERNAME=admin
      - ONVIF_PASSWORD=123456
      - ONVIF_AUTH_METHOD=both
      - ONVIF_PORT=8000
      - ONVIF_TEST_MODE=true
      - SERVER_IP=0.0.0.0
      - ANNOUNCE_IP=$host_ip
      - RTSP_API_PORT=$rtsp_http_port
      - WS_PORT=9999
      - LOW_RES_SENSORS_PER_PAGE=6
      - SENSORS_PER_PAGE=20
      - MAC_ADDRESS=51:12:56:73:D6:AA
    ports:
      - "554:554"
      - "$rtsp_http_port:$rtsp_http_port"
      - "9999:9999"
      - "3702:3702/udp"
    volumes:
      - /tmp/streams:/tmp/streams
    depends_on:
      - websocket-proxy
    networks:
      - yolink-network

networks:
  yolink-network:
    driver: bridge

volumes:
  redis-data:
EOF
    echo "docker-compose.yml generated successfully."
}

# Create IP monitor script
create_ip_monitor_script() {
    echo "Creating IP monitor script..."
    cat > "$APP_DIR/monitor-ip.sh" << 'EOT'
#!/bin/bash

# IP Monitor for YoLink CHEKT Integration
# This script monitors for IP address changes and updates configurations accordingly

# Exit on any error
set -e

APP_DIR="/opt/yolink-chekt"
LOG_FILE="/var/log/yolink-ip-monitor.log"
CURRENT_IP_FILE="$APP_DIR/current_ip.txt"
DOCKER_COMPOSE_FILE="$APP_DIR/docker-compose.yml"
LOCK_FILE="/tmp/yolink-ip-monitor.lock"
MAX_LOCK_AGE=300  # 5 minutes in seconds
RTSP_HTTP_PORT=8080  # Use the same port as in the main script

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Redirect output to log file with timestamps
exec > >(tee -a >(while read line; do echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line"; done >> "$LOG_FILE")) 2>&1

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Check and handle stale lock files
if [ -f "$LOCK_FILE" ]; then
    lock_time=$(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)
    current_time=$(date +%s)
    if [ $((current_time - lock_time)) -gt $MAX_LOCK_AGE ]; then
        echo "Removing stale lock file (older than $MAX_LOCK_AGE seconds)"
        rm -f "$LOCK_FILE"
    else
        echo "Another instance is already running (lock file exists)."
        exit 0
    fi
fi

# Create lock file
touch "$LOCK_FILE"

# Clean up lock file on exit
trap 'rm -f "$LOCK_FILE"; echo "Lock file removed."' EXIT

# Function to get the IP address
get_host_ip() {
    ip route get 8.8.8.8 | grep -o 'src [0-9.]*' | awk '{print $2}'
}

# Function to check if IP has changed
check_ip_changed() {
    local current_ip=$(get_host_ip)
    local stored_ip=""

    if [ -f "$CURRENT_IP_FILE" ]; then
        stored_ip=$(cat "$CURRENT_IP_FILE")
    fi

    if [ "$current_ip" != "$stored_ip" ]; then
        echo "IP address changed from $stored_ip to $current_ip"
        return 0  # IP has changed
    else
        echo "IP address unchanged: $current_ip"
        return 1  # IP has not changed
    fi
}

# Function to generate nginx.conf with the current IP
generate_nginx_conf() {
    local host_ip=$1
    local nginx_conf="$APP_DIR/nginx.conf"

    echo "Generating nginx.conf with IP $host_ip..."
    cat > "$nginx_conf" << EOF
server {
    listen 80;
    server_name localhost $host_ip;

    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name localhost $host_ip;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Improved SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

    # Add SSL session cache for better performance
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Main application
    location / {
        proxy_pass http://yolink_chekt:5000;

        # Standard proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Additional headers to help with redirection
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Server \$host;

        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Proxy RTSP HTTP API requests to port $RTSP_HTTP_PORT
    location /rtsp/ {
        proxy_pass http://rtsp-streamer:$RTSP_HTTP_PORT/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    echo "nginx.conf generated successfully."
}

# Generate SSL certificates with proper Subject Alternative Name (SAN)
generate_ssl_certificates() {
    local host_ip=$1
    local cert_dir=$2
    local cert_file="${cert_dir}/cert.pem"
    local key_file="${cert_dir}/key.pem"

    mkdir -p "$cert_dir"

    # Create a temporary OpenSSL configuration file
    local ssl_config=$(mktemp)
    cat > "$ssl_config" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = YoLink CHEKT Integration

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = $host_ip
EOF

    echo "Generating SSL certificates with IP $host_ip in SAN field..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$key_file" -out "$cert_file" \
        -config "$ssl_config"

    if [ $? -eq 0 ]; then
        echo "SSL certificates generated successfully with IP $host_ip in SAN field."
        # Verify the certificate
        echo "Certificate SAN field verification:"
        openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject Alternative Name"
    else
        echo "Failed to generate SSL certificates with SAN. Falling back to basic certificates..."
        openssl req -x509 -newkey rsa:2048 -keyout "$key_file" \
            -out "$cert_file" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=YoLink/CN=localhost"
    fi

    chmod 600 "$key_file" "$cert_file"
    rm -f "$ssl_config"
}

# Update docker-compose.yml with host IP
update_docker_compose_ip() {
    local host_ip=$1
    echo "Updating docker-compose.yml with TARGET_IP=$host_ip"

    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        echo "Error: docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
        exit 1
    fi

    cp "$DOCKER_COMPOSE_FILE" "${DOCKER_COMPOSE_FILE}.bak.$(date +%Y%m%d%H%M%S)" || {
        echo "Error: Failed to create backup of docker-compose.yml"
        exit 1
    }

    local tmpfile
    tmpfile=$(mktemp)
    while IFS= read -r line; do
        if echo "$line" | grep -q "TARGET_IP="; then
            local indent
            indent=$(echo "$line" | sed -E 's/^([[:space:]]*-).*/\1/')
            echo "${indent} TARGET_IP=$host_ip" >> "$tmpfile"
        elif echo "$line" | grep -q "ANNOUNCE_IP="; then
            local indent
            indent=$(echo "$line" | sed -E 's/^([[:space:]]*-).*/\1/')
            echo "${indent} ANNOUNCE_IP=$host_ip" >> "$tmpfile"
        else
            echo "$line" >> "$tmpfile"
        fi
    done < "$DOCKER_COMPOSE_FILE"

    # Validate the updated file
    if docker compose -f "$tmpfile" config >/dev/null 2>&1 || docker-compose -f "$tmpfile" config >/dev/null 2>&1; then
        mv "$tmpfile" "$DOCKER_COMPOSE_FILE" || {
            echo "Error: Failed to update docker-compose.yml"
            exit 1
        }
        echo "Successfully updated docker-compose.yml with IP addresses"
    else
        echo "Error: Invalid docker-compose.yml after update"
        rm -f "$tmpfile"
        exit 1
    fi
}

# Restart containers
restart_containers() {
    echo "Restarting containers to apply changes..."

    # Determine which Docker Compose command to use
    if docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD="docker compose"
    elif docker-compose --version >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD="docker-compose"
    else
        echo "Error: No Docker Compose command available."
        exit 1
    fi

    cd "$APP_DIR" || { echo "Cannot access $APP_DIR"; exit 1; }

    # Don't rebuild, just restart with the new config
    $DOCKER_COMPOSE_CMD down || { echo "Error: Failed to stop Docker containers"; exit 1; }
    $DOCKER_COMPOSE_CMD up -d || { echo "Error: Failed to start Docker containers"; exit 1; }

    echo "Containers restarted successfully"
}

# Main function
main() {
    echo "Starting IP monitor check..."

    if ! check_ip_changed; then
        echo "No IP change detected. Exiting."
        exit 0
    fi

    # Get the new IP
    HOST_IP=$(get_host_ip)

    # Store the new IP
    echo "$HOST_IP" > "$CURRENT_IP_FILE"

    # Update SSL certificates
    generate_ssl_certificates "$HOST_IP" "$APP_DIR/certs"

    # Update nginx.conf
    generate_nginx_conf "$HOST_IP"

    # Update docker-compose.yml
    update_docker_compose_ip "$HOST_IP"

    # Restart containers
    restart_containers

    echo "IP monitor check completed successfully."
}

# Run the main function
main
EOT

    chmod +x "$APP_DIR/monitor-ip.sh"
    echo "Created IP monitor script at $APP_DIR/monitor-ip.sh"
}

# Set up systemd service for IP monitoring
setup_ip_monitor_service() {
    echo "Setting up IP monitor systemd service and timer..."
    mkdir -p /etc/systemd/system

    # Create systemd service file
    cat > /etc/systemd/system/yolink-ip-monitor.service << 'EOF'
[Unit]
Description=YoLink CHEKT IP Address Monitor Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/yolink-chekt/monitor-ip.sh
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Create systemd timer file
    cat > /etc/systemd/system/yolink-ip-monitor.timer << 'EOF'
[Unit]
Description=Run YoLink CHEKT IP Address Monitor every 5 minutes
Requires=yolink-ip-monitor.service

[Timer]
Unit=yolink-ip-monitor.service
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

    # Reload systemd, enable and start the timer
    systemctl daemon-reload
    systemctl enable yolink-ip-monitor.timer
    systemctl start yolink-ip-monitor.timer
    echo "IP monitor service and timer installed. Checking for IP changes every 5 minutes."
}

# Backup a file if it exists
backup_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        cp "$src" "$dest" || { echo "Error: Failed to backup $(basename "$src")"; exit 1; }
        echo "Backed up $(basename "$src") to $(basename "$dest")"
    else
        echo "Note: $(basename "$src") not found, skipping backup"
    fi
}

# Restore a file if backup exists
restore_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        mv "$src" "$dest" || { echo "Error: Failed to restore $(basename "$dest")"; exit 1; }
        echo "Restored $(basename "$dest") from backup"
    else
        echo "Note: Backup $(basename "$src") not found, skipping restore"
    fi
}

# Download with retry logic
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry_delay=5
    local attempt=1

    while [ "$attempt" -le "$max_retries" ]; do
        echo "Downloading from $url (Attempt $attempt/$max_retries)..."
        if curl -L --fail "$url" -o "$output" 2>/tmp/curl_error; then
            echo "Download successful"
            return 0
        else
            local curl_err
            curl_err=$(cat /tmp/curl_error)
            echo "Download failed: $curl_err"
            if [ "$attempt" -eq "$max_retries" ]; then
                echo "Error: Failed to download repository after $max_retries attempts"
                exit 1
            fi
            sleep "$retry_delay"
            ((attempt++))
        fi
    done
}

#===================================
# INSTALLATION-SPECIFIC OPERATIONS
#===================================

if [ "$OPERATION_MODE" = "install" ]; then
    # Update package list
    echo "Updating package lists..."
    apt-get update || { echo "apt-get update failed."; exit 1; }

    # Install required dependencies
    echo "Installing required dependencies..."
    apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip software-properties-common rsync jq iproute2 openssl || { echo "Dependency installation failed."; exit 1; }

    # Detect the distribution
    DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
    DISTRO_VERSION=$(lsb_release -cs)
    echo "Detected distribution: $DISTRO $DISTRO_VERSION"

    # Install Docker if not already installed
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not found, installing Docker..."
        echo "Adding Docker GPG key..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || {
            echo "Adding Docker GPG key failed. Trying alternative method..."
            curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        }
        echo "Setting up Docker repository..."
        if [ -f /etc/apt/keyrings/docker.gpg ]; then
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO $DISTRO_VERSION stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        else
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$DISTRO $DISTRO_VERSION stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        fi
        apt-get update || { echo "apt-get update failed after adding Docker repository."; exit 1; }
        apt-get install -y docker-ce docker-ce-cli containerd.io || {
            echo "Docker installation failed. Trying alternative method..."
            curl -fsSL https://get.docker.com | sh
        }
    else
        echo "Docker is already installed."
    fi

    # Verify Docker installation
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker installation failed. Exiting."
        exit 1
    else
        echo "Docker is installed successfully."
        docker --version
    fi

    # Install Docker Compose plugin if not already installed
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose not found, installing Docker Compose plugin..."
        apt-get install -y docker-compose-plugin || {
            echo "Docker Compose plugin installation failed. Trying alternative method..."
            mkdir -p /usr/local/lib/docker/cli-plugins
            curl -SL https://github.com/docker/compose/releases/download/v2.24.6/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
            chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
        }
    else
        echo "Docker Compose is already installed."
    fi

    # Verify Docker Compose installation
    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose installation failed. Trying to install docker-compose standalone..."
        apt-get install -y docker-compose || {
            echo "Standalone docker-compose installation failed. Will continue without Docker Compose."
        }
    fi

    if docker compose version >/dev/null 2>&1; then
        echo "Docker Compose is installed successfully."
        docker compose version
    elif docker-compose --version >/dev/null 2>&1; then
        echo "Docker Compose (standalone) is installed successfully."
        docker-compose --version
    else
        echo "WARNING: Docker Compose installation failed. You will need to install it manually."
    fi

    # Create application directory
    echo "Creating application directory at $APP_DIR..."
    mkdir -p "$APP_DIR" || { echo "Failed to create $APP_DIR."; exit 1; }
    mkdir -p "$APP_DIR/logs" "$APP_DIR/templates" "$APP_DIR/certs"

    # Create initial .env file if it doesn't exist
    if [ ! -f "$APP_DIR/.env" ]; then
        echo "Creating default .env file..."
        cat <<EOT > "$APP_DIR/.env"
# RTSP Streamer Configuration
RTSP_PORT=554
RTSP_API_PORT=$RTSP_HTTP_PORT
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

    # Create Dockerfile.modbus-proxy if it doesn't exist
    if [ ! -f "$APP_DIR/Dockerfile.modbus-proxy" ]; then
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
    fi
fi

#===================================
# COMMON OPERATIONS FOR BOTH MODES
#===================================

# Get the current IP
HOST_IP=$(get_host_ip)

if [ "$OPERATION_MODE" = "install" ] || check_ip_changed; then
    # Generate/regenerate SSL certificates with proper SAN
    generate_ssl_certificates "$HOST_IP" "$APP_DIR/certs"

    # Store/update the current IP for future reference
    echo "$HOST_IP" > "$APP_DIR/current_ip.txt"

    # Create/update nginx.conf
    generate_nginx_conf "$HOST_IP"

    # If docker-compose.yml exists, update IPs
    if [ -f "$APP_DIR/docker-compose.yml" ] && [ "$OPERATION_MODE" = "update" ]; then
        # In update mode, find and replace the IPs
        sed -i "s/TARGET_IP=.*/TARGET_IP=$HOST_IP/g" "$APP_DIR/docker-compose.yml"
        sed -i "s/ANNOUNCE_IP=.*/ANNOUNCE_IP=$HOST_IP/g" "$APP_DIR/docker-compose.yml"
        # Update RTSP_API_PORT in case we need to change it
        sed -i "s/RTSP_API_PORT=.*/RTSP_API_PORT=$RTSP_HTTP_PORT/g" "$APP_DIR/docker-compose.yml"
    else
        # In install mode or if docker-compose.yml doesn't exist, generate it
        generate_docker_compose "$HOST_IP" "$RTSP_HTTP_PORT"
    fi
fi

# Download and extract the repository
echo "Downloading repository from $REPO_URL..."
download_with_retry "$REPO_URL" "$APP_DIR/repo.zip"

echo "Extracting repository..."
TEMP_DIR="$APP_DIR/temp-update"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR" || { echo "Failed to create temp directory"; exit 1; }
unzip -o "$APP_DIR/repo.zip" -d "$TEMP_DIR" || { echo "Unzip failed."; exit 1; }

# For updates, backup existing files that shouldn't be overwritten
if [ "$OPERATION_MODE" = "update" ]; then
    # Backup existing .env file
    backup_file "$APP_DIR/.env" "$APP_DIR/.env.bak"

    # Backup rtsp-streamer directory
    if [ -d "$APP_DIR/rtsp-streamer" ]; then
        echo "Backing up rtsp-streamer directory"
        rm -rf "$APP_DIR/rtsp-streamer.bak"
        cp -r "$APP_DIR/rtsp-streamer" "$APP_DIR/rtsp-streamer.bak" || { echo "Error: Failed to backup rtsp-streamer"; exit 1; }
    fi
fi

# Move extracted files and clean up
echo "Updating application files..."
rsync -a --exclude='.env' --exclude='docker-compose.yml' --exclude='nginx.conf' --exclude='monitor-ip.sh' --exclude='current_ip.txt' "$TEMP_DIR/yolink-chekt-main/" "$APP_DIR/" || { echo "Failed to sync updated files"; exit 1; }
rm -rf "$TEMP_DIR/yolink-chekt-main" "$APP_DIR/repo.zip"

# For updates, restore files that shouldn't be overwritten
if [ "$OPERATION_MODE" = "update" ]; then
    # Restore .env file from backup
    restore_file "$APP_DIR/.env.bak" "$APP_DIR/.env"

    # Update rtsp-streamer directory
    if [ -d "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" ]; then
        echo "Updating rtsp-streamer directory..."
        rm -rf "$APP_DIR/rtsp-streamer"
        cp -r "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" "$APP_DIR/" || { echo "Error: Failed to update rtsp-streamer"; exit 1; }
    elif [ -d "$APP_DIR/rtsp-streamer.bak" ]; then
        echo "Restoring rtsp-streamer from backup"
        cp -r "$APP_DIR/rtsp-streamer.bak" "$APP_DIR/rtsp-streamer" || { echo "Error: Failed to restore rtsp-streamer"; exit 1; }
    fi
fi

# Clean up temporary files
echo "Cleaning up..."
rm -rf "$TEMP_DIR"
rm -f "$APP_DIR/rtsp-streamer.bak" /tmp/curl_error 2>/dev/null || true

# Set permissions
echo "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || { echo "Failed to set directory permissions."; exit 1; }

# Create and set up IP monitor script and service
create_ip_monitor_script
setup_ip_monitor_service

# Determine which Docker Compose command to use
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif docker-compose --version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    echo "Error: No Docker Compose command available."
    exit 1
fi

# Build/start Docker containers
echo "Building/starting Docker containers..."
cd "$APP_DIR" || { echo "Failed to navigate to app directory."; exit 1; }
$DOCKER_COMPOSE_CMD down || { echo "Warning: Failed to stop Docker containers"; }
$DOCKER_COMPOSE_CMD up --build -d || { echo "Error: Failed to start Docker containers"; exit 1; }

# Copy self to app directory (if not already there)
if [ "$0" != "$APP_DIR/install.sh" ]; then
    echo "Copying installer script to $APP_DIR/install.sh..."
    cp "$0" "$APP_DIR/install.sh"
    chmod +x "$APP_DIR/install.sh"
fi

# Set up cron job to run updates
if command -v crontab >/dev/null 2>&1; then
    CRON_ENTRY="0 2 * * * $APP_DIR/install.sh --update >> /var/log/yolink-update.log 2>&1"
    CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")

    if ! echo "$CURRENT_CRON" | grep -q "$APP_DIR/install.sh --update"; then
        # Remove old self-update.sh entries if present
        NEW_CRON=$(echo "$CURRENT_CRON" | grep -v "$APP_DIR/self-update.sh")
        # Add new entry
        NEW_CRON="${NEW_CRON}\n${CRON_ENTRY}"
        echo -e "$NEW_CRON" | crontab -
        echo "Cron job set up to run daily updates at 2 AM."
    else
        echo "Cron job for updates already exists."
    fi
else
    echo "Cron not available; manual updates required."
fi

echo -e "\n\n======================================================================"
echo "YoLink CHEKT integration $([ "$OPERATION_MODE" = "install" ] && echo "installation" || echo "update") completed successfully."
echo "IP address monitoring is active and will check for changes every 5 minutes."
echo "Access the system at: https://$HOST_IP"
echo "Default login credentials: username=admin, password=admin123"
echo "======================================================================\n"