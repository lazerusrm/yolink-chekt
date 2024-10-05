# Yolink to CHEKT Integration

## Overview

This project integrates **Yolink** smart sensors (such as door contacts and motion sensors) with the **CHEKT** alarm system. The system uses an MQTT client to listen for sensor events and triggers the corresponding zones in the CHEKT system using its Local API. Additionally, a web interface is provided for mapping Yolink sensors to CHEKT zones.

## Features

- Real-time communication between Yolink sensors and CHEKT alarm system.
- Web-based GUI to manage sensor-to-zone mappings.
- Containerized solution for easy deployment and management.
- Automatic restart of services through Docker and systemd.

## Prerequisites

- **Docker** and **Docker Compose**: This program runs inside Docker containers.
- A Yolink local bridge or hub to connect Yolink sensors.
- CHEKT account and API access.

## Installation

You can install and run the program with a **single command**. This command will install Docker and Docker Compose (if necessary), clone the project from GitHub, build the containers, and start the system.

## Automatic Updates

The program can automatically check for updates from the GitHub repository and apply them. By default, a cron job is created during installation to check for updates daily at 2 AM.

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
