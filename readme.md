# Yolink to CHEKT Integration

## Overview

This project integrates **Yolink** smart sensors (such as door contacts and motion sensors) with the **CHEKT** alarm system. The system uses an MQTT client to listen for sensor events and triggers the corresponding zones in the CHEKT system using its Local API. Additionally, a web interface is provided for mapping Yolink sensors to CHEKT zones.

## Features

- **Containerized:** solution for easy deployment and management.
- **Automatic restart:** restart of services through Docker and systemd.
- **Device Management:** Monitor and update YoLink device states, battery levels, and last-seen times.
- **Alert Integration:** Supports CHEKT and SIA alert receivers for event notifications.
- **Web Interface:** Dashboard for device status, configuration page for settings, and user authentication with TOTP.
- **Real-Time Updates:** Uses MQTT for YoLink and monitor server communication.
- **Persistent Storage:** Stores device and mapping data in Redis, with YAML backups.
- **Automatic Updates:** Self-update script runs daily to keep the application current.

## Prerequisites

- **Docker:** Required for containerized deployment.
- **Docker Compose:** Used to manage multi-container setup (application + Redis).
- **Linux Host:** Scripts are tailored for Debian-based systems (e.g., Ubuntu).

## Installation

1. **Clone or Download the Repository:** 
   git clone https://github.com/lazerusrm/yolink-chekt.git
2. navigate to dir /yolink-chekt
3. sudo bash install.sh

Project Structure
app.py: Main Flask application with routes for dashboard, config, and auth.
config.py: Loads and saves config.yaml.
yolink_mqtt.py: Handles YoLink MQTT communication.
monitor_mqtt.py: Manages monitor server MQTT.
device_manager.py: Manages device data in Redis.
mappings.py: Handles device-to-zone mappings.
alerts.py: Triggers alerts to CHEKT/SIA (currently simplified).
templates/: HTML templates (index.html, config.html, login.html, setup_totp.html).
docker-compose.yml: Defines services (app + Redis).
install.sh: Initial setup script.
self-update.sh: Update script.
Requirements
See requirements.txt for Python dependencies. Key packages:

Flask, Flask-Login, Flask-Bcrypt
paho-mqtt, redis, PyYAML
pyotp, qrcode, cryptography   

## Automatic Updates

[The program can automatically check for updates from the GitHub repository and apply them. By default, a cron job is created during installation to check for updates daily at 2 AM.
](1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/lazerusrm/yolink-chekt.git
   cd yolink-chekt)
### How It Works:

- The program checks for new updates in the GitHub repository.
- If updates are found, the program pulls the latest changes, rebuilds the Docker containers, and restarts the service.
- Logs of the update process are saved in `/var/log/yolink-update.log`.

### Manual Update:

If you want to manually check for updates and apply them, run the following command:

```bash
/opt/yolink-chekt/self-update.sh

### Install Command:

```bash
curl -fsSL https://raw.githubusercontent.com/lazerusrm/yolink-chekt/main/install.sh | bash
