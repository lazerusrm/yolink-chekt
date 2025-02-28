# Yolink to CHEKT Integration - Version 1.1

## Overview

This project integrates **Yolink** smart sensors (e.g., door contacts, motion sensors) with the **CHEKT** alarm system.
It uses an MQTT client to listen for sensor events and triggers the corresponding zones in the CHEKT system via its local API.
Additionally, a web interface is provided for mapping Yolink sensors to CHEKT zones, configuring settings, and managing user authentication with TOTP.

## Features

- **Containerized Deployment:** Managed with Docker and Docker Compose.
- **Automatic Restart & Updates:** Services are automatically restarted via Docker/systemd and updated through a self-update script.
- **Device Management:** Real-time monitoring of sensor states, battery levels, and last-seen times, with data stored in Redis.
- **Alert Integration:** Supports both CHEKT and SIA alert receivers.
- **Prop Alarm Functionality:** When the door prop alarm is enabled, alerts are triggered only upon receiving an "openRemind" message, avoiding premature alerts from a simple closed-to-open transition.
- **Web Interface:** A dashboard for device status, configuration pages for settings, and secure user authentication (TOTP).
- **Persistent Storage:** Device and mapping data are stored in Redis, with YAML backups.
- **Automatic Updates:** A self-update mechanism checks for new GitHub releases daily at 2 AM.

## Prerequisites

- **Docker:** Required for containerized deployment.
- **Docker Compose:** Used for managing multi-container setups (application + Redis).
- **Linux Host:** Recommended for Debian-based systems (e.g., Ubuntu).

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/lazerusrm/yolink-chekt.git
