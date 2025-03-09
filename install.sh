#!/bin/bash

# YoLink CHEKT Integration - Unified Robust Installation and Update Script
# This script handles both first-time installation and updates with zero manual edits required
VERSION="1.2.0"

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
ERRORS_ENCOUNTERED=0
ERROR_LOG=""
TOTAL_STEPS=10
CURRENT_STEP=0
DEBUG_MODE=false

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
    --ip=*)
      HOST_IP_OVERRIDE="${arg#*=}"
      shift
      ;;
    --debug)
      DEBUG_MODE=true
      shift
      ;;
    --help)
      echo "Usage: $0 [--install|--update|--ip=<IP>|--debug|--help]"
      echo ""
      echo "Options:"
      echo "  --install     Force installation mode even if existing installation is detected"
      echo "  --update      Force update mode even if no existing installation is detected"
      echo "  --ip=<IP>     Specify the host IP address manually"
      echo "  --debug       Enable debug mode with additional logging"
      echo "  --help        Show this help message"
      echo ""
      echo "Without options, the script will automatically detect whether to install or update."
      exit 0
      ;;
  esac
done

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Redirect output to log file with timestamps
if [ "$DEBUG_MODE" = "true" ]; then
    # More verbose logging in debug mode
    exec > >(tee -a >(while read line; do echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line"; done >> "$LOG_FILE"))
    exec 2>&1
    set -x  # Print commands as they execute
else
    # Standard logging
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

#===================================
# LOGGING AND ERROR HANDLING FUNCTIONS
#===================================

# Function to log errors with timestamp
log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[ERROR] $timestamp - $1"
    ERROR_LOG="${ERROR_LOG}\n${message}"
    echo -e "\e[31m${message}\e[0m" # Red color for errors
    ((ERRORS_ENCOUNTERED++))
}

# Function to log warnings with timestamp
log_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[WARNING] $timestamp - $1"
    echo -e "\e[33m${message}\e[0m" # Yellow color for warnings
}

# Function to log info with timestamp
log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[INFO] $timestamp - $1"
    echo -e "\e[36m${message}\e[0m" # Cyan color for info
}

# Function to log success with timestamp
log_success() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[SUCCESS] $timestamp - $1"
    echo -e "\e[32m${message}\e[0m" # Green color for success
}

# Function to handle errors and exit if critical
handle_error() {
    local error_message="$1"
    local is_critical="${2:-false}"

    log_error "$error_message"

    if [ "$is_critical" = "true" ]; then
        log_error "Critical error encountered. Exiting installation."
        if [ -n "$ERROR_LOG" ]; then
            echo -e "\nError summary:"
            echo -e "$ERROR_LOG"
        fi
        exit 1
    fi
}

# Function to track installation progress
track_progress() {
    ((CURRENT_STEP++))
    log_info "Step $CURRENT_STEP/$TOTAL_STEPS: $1"
}

# Function to verify a command was successful
verify_success() {
    local exit_code=$?
    local error_message="$1"
    local is_critical="${2:-false}"

    if [ $exit_code -ne 0 ]; then
        handle_error "$error_message" "$is_critical"
        return 1
    fi
    return 0
}

#===================================
# ROBUST IP ADDRESS HANDLING
#===================================

# Function to get the IP address silently (no logging during capture)
get_host_ip_silent() {
    # Try multiple methods to get the IP address
    local host_ip=""

    # Method 1: Using ip route (most common)
    if command -v ip >/dev/null 2>&1; then
        host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print $2}')
    fi

    # Method 2: Using hostname (fallback)
    if [ -z "$host_ip" ] && command -v hostname >/dev/null 2>&1; then
        host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    # Method 3: Using ifconfig (older systems)
    if [ -z "$host_ip" ] && command -v ifconfig >/dev/null 2>&1; then
        host_ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
    fi

    # Validate IP format
    if [[ ! "$host_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi

    echo "$host_ip"
    return 0
}

# Function to get the IP address with logging and fallback mechanisms
get_host_ip() {
    local host_ip

    log_info "Detecting host IP address..."

    # Try to get the IP address silently
    host_ip=$(get_host_ip_silent)

    # If unsuccessful, try alternative methods
    if [ -z "$host_ip" ]; then
        log_warning "Could not determine IP address using primary method. Trying alternatives..."

        # Try to use an environment variable if set
        if [ -n "$HOST_IP_OVERRIDE" ]; then
            log_info "Using IP from environment variable: $HOST_IP_OVERRIDE"
            host_ip="$HOST_IP_OVERRIDE"
        else
            # Ask user for IP address if in interactive mode
            if [ -t 0 ]; then
                log_info "Please enter the host IP address manually:"
                read -r host_ip
                if [[ ! "$host_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    handle_error "Invalid IP address format entered manually" true
                fi
            else
                handle_error "Failed to detect IP address automatically" true
            fi
        fi
    fi

    log_success "Using host IP address: $host_ip"
    echo "$host_ip"
}

# Function to save IP address for future reference
save_host_ip() {
    local host_ip="$1"
    local ip_file="$APP_DIR/current_ip.txt"

    if [ -f "$ip_file" ]; then
        # Backup existing file
        cp "$ip_file" "${ip_file}.bak" 2>/dev/null || log_warning "Failed to backup current IP file"
    fi

    # Save the new IP
    echo "$host_ip" > "$ip_file"
    verify_success "Failed to save IP address to $ip_file" false

    log_info "IP address saved to $ip_file"
}

# Function to check if IP has changed
check_ip_changed() {
    local current_ip=$(get_host_ip_silent)
    local stored_ip=""

    if [ -f "$APP_DIR/current_ip.txt" ]; then
        stored_ip=$(cat "$APP_DIR/current_ip.txt")
    fi

    if [ "$current_ip" != "$stored_ip" ]; then
        log_info "IP address changed from $stored_ip to $current_ip"
        return 0  # IP has changed
    else
        log_info "IP address unchanged: $current_ip"
        return 1  # IP has not changed
    fi
}

#===================================
# ROBUST SSL CERTIFICATE GENERATION
#===================================

# Function to generate basic SSL certificates without SAN
generate_basic_certificate() {
    local cert_file="$1"
    local key_file="$2"
    local error_output="/tmp/openssl_basic_error_$$.txt"

    log_info "Generating basic SSL certificates without SAN field..."

    openssl req -x509 -newkey rsa:2048 -keyout "$key_file" \
        -out "$cert_file" -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=YoLink/CN=localhost" 2>"$error_output"

    if [ $? -eq 0 ]; then
        log_success "Basic SSL certificates generated successfully"
    else
        log_error "Failed to generate even basic SSL certificates. Error details:"
        cat "$error_output"
        return 1
    fi

    # Clean up
    rm -f "$error_output" 2>/dev/null
    return 0
}

# Function to generate SSL certificates with proper error handling
generate_ssl_certificates() {
    local host_ip="$1"
    local cert_dir="$2"
    local cert_file="${cert_dir}/cert.pem"
    local key_file="${cert_dir}/key.pem"
    local error_output="/tmp/openssl_error_$$.txt"

    log_info "Generating SSL certificates..."

    # Create certificate directory if it doesn't exist
    mkdir -p "$cert_dir" 2>/dev/null
    verify_success "Failed to create certificate directory at $cert_dir" true

    # Create a temporary OpenSSL configuration file
    local ssl_config
    ssl_config=$(mktemp)
    verify_success "Failed to create temporary file for OpenSSL configuration" true

    log_info "Creating OpenSSL configuration..."

    # Write configuration to file with proper error handling
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

    verify_success "Failed to write OpenSSL configuration file" true

    # Verify the config file was created correctly
    if [ ! -s "$ssl_config" ]; then
        handle_error "OpenSSL configuration file is empty" false
        log_warning "Falling back to basic certificate generation without SAN..."
        generate_basic_certificate "$cert_file" "$key_file"
        return 0
    fi

    # Display config for debugging if in debug mode
    if [ "$DEBUG_MODE" = "true" ]; then
        log_info "OpenSSL config file contents:"
        cat "$ssl_config"
    fi

    # Generate certificates with SAN field
    log_info "Generating certificates with SAN field..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$key_file" -out "$cert_file" \
        -config "$ssl_config" 2>"$error_output"

    if [ $? -eq 0 ]; then
        log_success "SSL certificates generated successfully with IP $host_ip in SAN field"
        # Verify the certificate (optional)
        if [ "$DEBUG_MODE" = "true" ]; then
            log_info "Certificate SAN field verification:"
            openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject Alternative Name"
        fi
    else
        log_warning "Failed to generate SSL certificates with SAN. Error details:"
        cat "$error_output"
        log_warning "Falling back to basic certificate generation without SAN..."
        generate_basic_certificate "$cert_file" "$key_file"
    fi

    # Set proper permissions
    chmod 600 "$key_file" "$cert_file" 2>/dev/null
    verify_success "Failed to set proper permissions on certificates" false

    # Clean up
    rm -f "$ssl_config" "$error_output" 2>/dev/null || true
}

#===================================
# ROBUST CONFIGURATION GENERATION
#===================================

# Function to generate nginx.conf
generate_nginx_conf() {
    local host_ip="$1"
    local nginx_conf="$APP_DIR/nginx.conf"
    local rtsp_http_port="${2:-8080}"

    log_info "Generating nginx.conf with IP $host_ip..."

    # Backup existing file if it exists
    if [ -f "$nginx_conf" ]; then
        cp "$nginx_conf" "${nginx_conf}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
        verify_success "Failed to backup existing nginx.conf" false
    fi

    # Generate the nginx configuration
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

    # Proxy RTSP HTTP API requests
    location /rtsp/ {
        proxy_pass http://rtsp-streamer:$rtsp_http_port/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    verify_success "Failed to generate nginx.conf" true
    log_success "nginx.conf generated successfully with server_name: localhost $host_ip"
}

# Function to generate or update docker-compose.yml
generate_docker_compose() {
    local host_ip="$1"
    local rtsp_http_port="${2:-8080}"
    local docker_compose_file="$APP_DIR/docker-compose.yml"

    log_info "Generating docker-compose.yml with IP $host_ip..."

    # Backup existing file if it exists
    if [ -f "$docker_compose_file" ]; then
        cp "$docker_compose_file" "${docker_compose_file}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
        verify_success "Failed to backup existing docker-compose.yml" false
    fi

    # Generate the docker-compose.yml file
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
      - DISABLE_HTTPS=true
      - QUART_DEBUG=true
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

    verify_success "Failed to generate docker-compose.yml" true
    log_success "docker-compose.yml generated successfully with TARGET_IP=$host_ip"
}

#===================================
# DEPENDENCY CHECKS AND INSTALLATION
#===================================

# Function to check required dependencies
check_dependencies() {
    log_info "Checking required dependencies..."

    local missing_deps=()

    # Check for essential commands
    for cmd in curl openssl ip awk grep sed; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done

    # Check for Docker-related commands
    if ! command -v docker >/dev/null 2>&1; then
        missing_deps+=("docker")
    fi

    # Report missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warning "Missing dependencies: ${missing_deps[*]}"

        # Attempt to install missing dependencies
        if command -v apt-get >/dev/null 2>&1; then
            log_info "Attempting to install missing dependencies with apt-get..."
            apt-get update -qq
            apt-get install -y -qq "${missing_deps[@]}" >/dev/null 2>&1

            # Verify installation
            still_missing=()
            for cmd in "${missing_deps[@]}"; do
                if ! command -v $cmd >/dev/null 2>&1; then
                    still_missing+=("$cmd")
                fi
            done

            if [ ${#still_missing[@]} -gt 0 ]; then
                handle_error "Failed to install required dependencies: ${still_missing[*]}" true
            else
                log_success "Successfully installed all missing dependencies"
            fi
        else
            handle_error "Please install required dependencies: ${missing_deps[*]}" true
        fi
    else
        log_success "All required dependencies are installed"
    fi
}

# Install Docker if not available
install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log_info "Docker is already installed"
        return 0
    fi

    log_info "Installing Docker..."

    # Detect the distribution
    DISTRO=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]') || DISTRO="unknown"
    DISTRO_VERSION=$(lsb_release -cs 2>/dev/null) || DISTRO_VERSION="unknown"
    log_info "Detected distribution: $DISTRO $DISTRO_VERSION"

    if [ "$DISTRO" = "unknown" ]; then
        # Try alternative detection methods
        if [ -f /etc/os-release ]; then
            DISTRO=$(. /etc/os-release && echo "$ID")
            DISTRO_VERSION=$(. /etc/os-release && echo "$VERSION_CODENAME")
            log_info "Detected from os-release: $DISTRO $DISTRO_VERSION"
        fi
    fi

    # Install Docker using the appropriate method
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        # Install using official Docker repository
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO $DISTRO_VERSION stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
    else
        # Use the convenience script as fallback
        log_info "Using Docker convenience script for installation..."
        curl -fsSL https://get.docker.com | sh
    fi

    if ! command -v docker >/dev/null 2>&1; then
        handle_error "Failed to install Docker" true
        return 1
    fi

    # Install Docker Compose
    log_info "Installing Docker Compose..."
    if ! docker compose version >/dev/null 2>&1; then
        # Try to install Docker Compose plugin first
        apt-get install -y docker-compose-plugin || {
            log_warning "Docker Compose plugin installation failed. Installing standalone docker-compose..."
            apt-get install -y docker-compose || {
                log_warning "Standalone docker-compose installation failed. Downloading binary..."
                mkdir -p /usr/local/lib/docker/cli-plugins
                curl -SL https://github.com/docker/compose/releases/download/v2.24.6/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
                chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
            }
        }
    fi

    log_success "Docker and Docker Compose installed successfully"
    return 0
}

#===================================
# FILE AND DOWNLOAD MANAGEMENT
#===================================

# Backup a file if it exists
backup_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        cp "$src" "$dest" || {
            log_warning "Failed to backup $(basename "$src")"
            return 1
        }
        log_info "Backed up $(basename "$src") to $(basename "$dest")"
        return 0
    else
        log_info "Note: $(basename "$src") not found, skipping backup"
        return 0
    fi
}

# Restore a file if backup exists
restore_file() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        mv "$src" "$dest" || {
            log_warning "Failed to restore $(basename "$dest")"
            return 1
        }
        log_info "Restored $(basename "$dest") from backup"
        return 0
    else
        log_info "Note: Backup $(basename "$src") not found, skipping restore"
        return 0
    fi
}

# Download with retry logic
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry_delay=5
    local attempt=1
    local error_output="/tmp/curl_error_$$.txt"

    while [ "$attempt" -le "$max_retries" ]; do
        log_info "Downloading from $url (Attempt $attempt/$max_retries)..."
        if curl -L --fail "$url" -o "$output" 2>"$error_output"; then
            log_success "Download successful"
            rm -f "$error_output"
            return 0
        else
            local curl_err
            curl_err=$(cat "$error_output")
            log_warning "Download failed: $curl_err"
            if [ "$attempt" -eq "$max_retries" ]; then
                handle_error "Failed to download repository after $max_retries attempts" true
                rm -f "$error_output"
                return 1
            fi
            sleep "$retry_delay"
            ((attempt++))
        fi
    done

    rm -f "$error_output"
    return 1
}

#===================================
# CONTAINER MANAGEMENT
#===================================

# Function to determine which Docker Compose command to use
get_docker_compose_cmd() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        return 1
    fi
    return 0
}

# Function to restart containers with proper error handling
restart_containers() {
    local timeout="${1:-300}"  # Default timeout: 5 minutes

    log_info "Restarting containers to apply changes..."

    # Determine which Docker Compose command to use
    local DOCKER_COMPOSE_CMD
    DOCKER_COMPOSE_CMD=$(get_docker_compose_cmd)

    if [ $? -ne 0 ]; then
        handle_error "No Docker Compose command available" true
        return 1
    fi

    # Change to the application directory
    cd "$APP_DIR" || {
        handle_error "Cannot access $APP_DIR" true
        return 1
    }

    # Stop containers with timeout
    log_info "Stopping containers..."
    $DOCKER_COMPOSE_CMD down --timeout $timeout || {
        log_warning "Failed to stop Docker containers gracefully. Forcing stop..."
        $DOCKER_COMPOSE_CMD down -v --remove-orphans
    }

    # Start containers
    log_info "Starting containers with build..."
    $DOCKER_COMPOSE_CMD up -d --build

    if [ $? -eq 0 ]; then
        log_success "Containers started successfully"

        # Verify containers are running (only in debug mode to avoid polluting logs)
        if [ "$DEBUG_MODE" = "true" ]; then
            log_info "Verifying container status..."
            $DOCKER_COMPOSE_CMD ps
        fi
    else
        handle_error "Failed to start Docker containers" true
        return 1
    fi

    return 0
}

#===================================
# IP MONITORING SETUP
#===================================

# Create IP monitor script
create_ip_monitor_script() {
    log_info "Creating IP monitor script..."
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
    # Try multiple methods to get IP
    local host_ip=""

    # Method 1: Using ip route
    if command -v ip >/dev/null 2>&1; then
        host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print $2}')
    fi

    # Method 2: Using hostname
    if [ -z "$host_ip" ] && command -v hostname >/dev/null 2>&1; then
        host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    # Method 3: Using ifconfig
    if [ -z "$host_ip" ] && command -v ifconfig >/dev/null 2>&1; then
        host_ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
    fi

    # Validate IP format
    if [[ ! "$host_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Could not detect a valid IP address."
        exit 1
    fi

    echo "$host_ip"
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
    local rtsp_http_port=8080

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

    # Proxy RTSP HTTP API requests to port $rtsp_http_port
    location /rtsp/ {
        proxy_pass http://rtsp-streamer:$rtsp_http_port/;
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
        -config "$ssl_config" 2>/tmp/openssl_error

    if [ $? -eq 0 ]; then
        echo "SSL certificates generated successfully with IP $host_ip in SAN field."
        # Verify the certificate
        echo "Certificate SAN field verification:"
        openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject Alternative Name"
    else
        echo "Failed to generate SSL certificates with SAN. Error:"
        cat /tmp/openssl_error
        echo "Falling back to basic certificates..."
        openssl req -x509 -newkey rsa:2048 -keyout "$key_file" \
            -out "$cert_file" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=YoLink/CN=localhost"
    fi

    chmod 600 "$key_file" "$cert_file"
    rm -f "$ssl_config" /tmp/openssl_error 2>/dev/null || true
}

# Update docker-compose.yml with host IP
update_docker_compose_ip() {
    local host_ip=$1
    local docker_compose_file="$APP_DIR/docker-compose.yml"
    local rtsp_http_port=8080

    echo "Creating new docker-compose.yml with IP $host_ip..."

    # Create a backup of the original file
    cp "$docker_compose_file" "${docker_compose_file}.bak.$(date +%Y%m%d%H%M%S)" || {
        echo "Warning: Failed to create backup of docker-compose.yml"
    }

    # Generate a new docker-compose.yml file
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
      - DISABLE_HTTPS=true
      - QUART_DEBUG=true
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

    # Verify the file was created
    if [ -s "$docker_compose_file" ]; then
        echo "docker-compose.yml generated successfully with IP addresses"
    else
        echo "Error: Failed to generate docker-compose.yml"
        # Try to restore from backup
        local latest_backup=$(ls -t "${docker_compose_file}.bak."* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            echo "Attempting to restore from backup: $latest_backup"
            cp "$latest_backup" "$docker_compose_file" || {
                echo "Error: Failed to restore backup"
                exit 1
            }
        else
            echo "Error: No backup available to restore"
            exit 1
        fi
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
    log_success "Created IP monitor script at $APP_DIR/monitor-ip.sh"
}

# Set up systemd service for IP monitoring
setup_ip_monitor_service() {
    log_info "Setting up IP monitor systemd service and timer..."
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
    log_success "IP monitor service and timer installed. Checking for IP changes every 5 minutes."
}

#===================================
# MAIN EXECUTION
#===================================

log_info "Starting YoLink CHEKT $OPERATION_MODE (script version $VERSION) at $(date)"

# Check if this script is being executed as self-update.sh
SCRIPT_NAME=$(basename "$0")
if [ "$SCRIPT_NAME" = "self-update.sh" ]; then
    log_info "Detected execution as self-update.sh, running in update mode."
    OPERATION_MODE="update"

    # Create a symlink to install.sh for future runs
    if [ ! -L "$APP_DIR/self-update.sh" ] && [ -f "$APP_DIR/install.sh" ]; then
        log_info "Creating symbolic link from self-update.sh to install.sh"
        ln -sf "$APP_DIR/install.sh" "$APP_DIR/self-update.sh"
    fi

    # Update cron job to use install.sh directly in future
    if command -v crontab >/dev/null 2>&1; then
        CRON_ENTRY="0 2 * * * $APP_DIR/install.sh --update >> /var/log/yolink-update.log 2>&1"
        CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
        if echo "$CURRENT_CRON" | grep -q "$APP_DIR/self-update.sh"; then
            log_info "Updating cron job to use install.sh instead of self-update.sh"
            NEW_CRON=$(echo "$CURRENT_CRON" | sed "s|$APP_DIR/self-update.sh|$APP_DIR/install.sh --update|g")
            echo "$NEW_CRON" | crontab -
        fi
    fi
fi

# Auto-detect operation mode if not specified
if [ "$OPERATION_MODE" = "auto" ]; then
    if [ -d "$APP_DIR" ] && [ -f "$APP_DIR/current_ip.txt" ]; then
        OPERATION_MODE="update"
        log_info "Detected existing installation. Running in update mode."
    else
        OPERATION_MODE="install"
        log_info "No existing installation detected. Running in install mode."
    fi
fi

# Step 1: Check Dependencies
track_progress "Checking system dependencies"
check_dependencies

# Step 2: Get Host IP
track_progress "Detecting host IP"
HOST_IP=${HOST_IP_OVERRIDE:-$(get_host_ip)}

# Step 3: Installation-specific operations
if [ "$OPERATION_MODE" = "install" ]; then
    track_progress "Setting up initial environment"

    # Update package list
    log_info "Updating package lists..."
    apt-get update || log_warning "apt-get update failed. Continuing anyway."

    # Install required dependencies
    log_info "Installing required dependencies..."
    apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip software-properties-common rsync jq iproute2 openssl || log_warning "Some dependency installation failed. Continuing anyway."

    # Install Docker if needed
    install_docker

    # Create application directory
    log_info "Creating application directory at $APP_DIR..."
    mkdir -p "$APP_DIR" "$APP_DIR/logs" "$APP_DIR/templates" "$APP_DIR/certs"
    verify_success "Failed to create application directories" true

    # Create initial .env file if it doesn't exist
    if [ ! -f "$APP_DIR/.env" ]; then
        log_info "Creating default .env file..."
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
        log_info "Creating Dockerfile.modbus-proxy..."
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

# Step 4: Update/Create configuration files
track_progress "Updating configuration files"

# Store/update the current IP for future reference
save_host_ip "$HOST_IP"

# Generate/regenerate SSL certificates with proper SAN
generate_ssl_certificates "$HOST_IP" "$APP_DIR/certs"

# Create/update nginx.conf
generate_nginx_conf "$HOST_IP" "$RTSP_HTTP_PORT"

# Generate/update docker-compose.yml
generate_docker_compose "$HOST_IP" "$RTSP_HTTP_PORT"

# Step 5: Download and extract repository
track_progress "Downloading and extracting repository"
log_info "Downloading repository from $REPO_URL..."
download_with_retry "$REPO_URL" "$APP_DIR/repo.zip"
verify_success "Failed to download repository" true

log_info "Extracting repository..."
TEMP_DIR="$APP_DIR/temp-update"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR" || handle_error "Failed to create temp directory" true
unzip -o "$APP_DIR/repo.zip" -d "$TEMP_DIR" || handle_error "Unzip failed" true

# Step 6: Backup existing files that shouldn't be overwritten
if [ "$OPERATION_MODE" = "update" ]; then
    track_progress "Backing up existing files"

    # Backup existing .env file
    backup_file "$APP_DIR/.env" "$APP_DIR/.env.bak"

    # Backup rtsp-streamer directory
    if [ -d "$APP_DIR/rtsp-streamer" ]; then
        log_info "Backing up rtsp-streamer directory"
        rm -rf "$APP_DIR/rtsp-streamer.bak"
        cp -r "$APP_DIR/rtsp-streamer" "$APP_DIR/rtsp-streamer.bak" || log_warning "Failed to backup rtsp-streamer"
    fi
}

# Step 7: Move extracted files and clean up
track_progress "Updating application files"
log_info "Syncing updated files..."
rsync -a --exclude='.env' --exclude='docker-compose.yml' --exclude='nginx.conf' --exclude='monitor-ip.sh' --exclude='current_ip.txt' "$TEMP_DIR/yolink-chekt-main/" "$APP_DIR/" || handle_error "Failed to sync updated files" true
rm -rf "$TEMP_DIR/yolink-chekt-main" "$APP_DIR/repo.zip"

# Step 8: For updates, restore files that shouldn't be overwritten
if [ "$OPERATION_MODE" = "update" ]; then
    track_progress "Restoring configuration files"

    # Restore .env file from backup
    restore_file "$APP_DIR/.env.bak" "$APP_DIR/.env"

    # Update rtsp-streamer directory
    if [ -d "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" ]; then
        log_info "Updating rtsp-streamer directory..."
        rm -rf "$APP_DIR/rtsp-streamer"
        cp -r "$TEMP_DIR/yolink-chekt-main/rtsp-streamer" "$APP_DIR/" || log_warning "Failed to update rtsp-streamer"
    elif [ -d "$APP_DIR/rtsp-streamer.bak" ]; then
        log_info "Restoring rtsp-streamer from backup"
        cp -r "$APP_DIR/rtsp-streamer.bak" "$APP_DIR/rtsp-streamer" || log_warning "Failed to restore rtsp-streamer"
    fi
}

# Step 9: Clean up temporary files
log_info "Cleaning up..."
rm -rf "$TEMP_DIR"
rm -f "$APP_DIR/rtsp-streamer.bak" /tmp/curl_error_* /tmp/openssl_* 2>/dev/null || true

# Step 10: Set permissions
log_info "Setting permissions..."
chmod -R u+rwX,go+rX "$APP_DIR" || handle_error "Failed to set directory permissions" false

# Step 11: Create and set up IP monitor script and service
track_progress "Setting up IP monitoring"
create_ip_monitor_script
setup_ip_monitor_service

# Step 12: Build/start Docker containers
track_progress "Starting Docker containers"
restart_containers

# Step 13: Copy self to app directory (if not already there)
if [ "$0" != "$APP_DIR/install.sh" ]; then
    log_info "Copying installer script to $APP_DIR/install.sh..."
    cp "$0" "$APP_DIR/install.sh"
    chmod +x "$APP_DIR/install.sh"
}

# Step 14: Set up cron job to run updates
if command -v crontab >/dev/null 2>&1; then
    log_info "Setting up cron job for automatic updates..."
    CRON_ENTRY="0 2 * * * $APP_DIR/install.sh --update >> /var/log/yolink-update.log 2>&1"
    CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")

    if ! echo "$CURRENT_CRON" | grep -q "$APP_DIR/install.sh --update"; then
        # Remove old self-update.sh entries if present
        NEW_CRON=$(echo "$CURRENT_CRON" | grep -v "$APP_DIR/self-update.sh")
        # Add new entry
        NEW_CRON="${NEW_CRON}\n${CRON_ENTRY}"
        echo -e "$NEW_CRON" | crontab -
        log_success "Cron job set up to run daily updates at 2 AM."
    else
        log_info "Cron job for updates already exists."
    fi
else
    log_warning "Cron not available; manual updates will be required."
fi

# Print summary
echo -e "\n\n======================================================================"
echo "YoLink CHEKT integration $([ "$OPERATION_MODE" = "install" ] && echo "installation" || echo "update") completed with $([ $ERRORS_ENCOUNTERED -eq 0 ] && echo "no errors" || echo "$ERRORS_ENCOUNTERED errors")."
echo "IP address monitoring is active and will check for changes every 5 minutes."
echo "Access the system at: https://$HOST_IP"
echo "Default login credentials: username=admin, password=admin123"
if [ $ERRORS_ENCOUNTERED -gt 0 ]; then
    echo -e "\nWarning: Some errors were encountered during the process."
    echo "Please check the log file for details: $LOG_FILE"
fi
echo "======================================================================\n"

exit ${ERRORS_ENCOUNTERED:-0}