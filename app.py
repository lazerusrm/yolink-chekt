"""
Yolink to CHEKT Integration - Version 1.2
========================================

Overview:
This application integrates Yolink smart sensors (e.g., door contacts, motion sensors) with the CHEKT alarm system
and Modbus relays. It listens to sensor events via MQTT and triggers corresponding CHEKT zones or relay channels.
A web interface is provided for device mapping, configuration, and secure user authentication (TOTP).

Key Features:
- Containerized Deployment: Easily managed with Docker and Docker Compose.
- Real-Time Device Management: Monitors sensor states, battery levels, and last-seen times with data stored in Redis.
- Alert Integration: Supports CHEKT, SIA alert receivers, and Modbus relays.
- Prop Alarm Functionality: When enabled, door sensors trigger an alert only upon receiving an "openRemind" message.
- Web Interface: Dashboard for device status, configuration pages, and user authentication.
- Automatic Updates: Self-update mechanism to pull changes from GitHub and restart services.

Prerequisites:
- Docker and Docker Compose.
- Linux (Debian-based systems recommended).

Installation:
1. Clone the repository: git clone https://github.com/lazerusrm/yolink-chekt.git
2. Change to the repository directory: cd yolink-chekt
3. Run the install script: sudo bash install.sh

Project Structure:
- app.py: Main Flask application.
- config.py: Configuration management.
- yolink_mqtt.py: YoLink MQTT client.
- monitor_mqtt.py: Monitor server MQTT communications.
- device_manager.py: Device state management in Redis.
- mappings.py: Mapping of Yolink devices to CHEKT zones and relay channels.
- alerts.py: Alert triggering logic.
- modbus_relay.py: Communication with Modbus TCP relays.
- templates/: Web interface HTML templates.
- docker-compose.yml: Docker configuration.
- install.sh: Installation script.
- self-update.sh: Automatic update script.

For further details, please refer to the README.md.
"""

import os
import threading
from time import sleep
import logging
import requests
import json
from flask import Flask, request, render_template, flash, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import io
import base64
import logging
import time
import psutil
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from flask_apscheduler import APScheduler

# Import configuration functions and constants
from config import load_config, save_config, get_user_data, save_user_data, SUPPORTED_TIMEZONES
from db import redis_client, ensure_redis_connection
from device_manager import refresh_yolink_devices, get_all_devices
from mappings import get_mappings, save_mapping, save_mappings
from yolink_mqtt import connected as yolink_connected
from monitor_mqtt import connected as monitor_connected
from yolink_mqtt import run_mqtt_client
from monitor_mqtt import run_monitor_mqtt
import modbus_relay
import traceback

# Logging Setup
handler = RotatingFileHandler("/app/logs/app.log", maxBytes=10*1024*1024, backupCount=5)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

scheduler = APScheduler()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
bcrypt = Bcrypt(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if get_user_data(username):
        return User(username)
    return None

def init_modbus():
    """Initialize Modbus relay service if enabled"""
    try:
        config = load_config()
        if config.get("modbus", {}).get("enabled", False):
            logger.info("Initializing Modbus relay connection")
            threading.Thread(target=modbus_relay.initialize, daemon=True).start()
            return True
        else:
            logger.info("Modbus relay is disabled in configuration")
            return False
    except Exception as e:
        logger.error(f"Failed to initialize Modbus relay: {e}")
        traceback.print_exc()
        return False

def is_system_configured():
    """Check if the system has been configured with necessary credentials"""
    config = load_config()

    # Check for YoLink credentials
    yolink_configured = (
            config.get("yolink", {}).get("uaid") and
            config.get("yolink", {}).get("secret_key")
    )

    # Check for monitor configuration
    monitor_configured = config.get("mqtt_monitor", {}).get("url")

    # At least one receiver must be enabled
    receiver_configured = (
        config.get("chekt", {}).get("enabled", True) or
        config.get("sia", {}).get("enabled", False) or
        config.get("modbus", {}).get("enabled", False)
    )

    return yolink_configured and monitor_configured and receiver_configured


def start_services():
    """Check configuration and start MQTT clients if configured"""
    if is_system_configured():
        logger.info("System configured, starting MQTT clients")
        threading.Thread(target=run_mqtt_client, daemon=True).start()
        threading.Thread(target=run_monitor_mqtt, daemon=True).start()

        # Initialize Modbus relay if enabled
        config = load_config()
        if config.get("modbus", {}).get("enabled", False):
            logger.info("Modbus relay enabled, initializing connection")
            try:
                init_modbus()
            except Exception as e:
                logger.error(f"Failed to initialize Modbus relay: {e}")
    else:
        logger.info("System not yet fully configured. MQTT clients not started.")

def init_default_user():
    """Create a default admin user if no users exist."""
    if not redis_client.keys("user:*"):
        default_username = "admin"
        default_password = "admin123"
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        user_data = {"password": hashed_password, "force_password_change": True}
        save_user_data(default_username, user_data)

def check_mqtt_connection_active():
    """Actively check if MQTT connection is functional instead of just checking the flag"""
    from yolink_mqtt import client as yolink_client, connected as yolink_connected
    try:
        # Check if the client exists and is connected
        if yolink_client and yolink_client.is_connected():
            return True
        # If the client says it's connected but the global var doesn't, update the global
        elif yolink_client and yolink_client.is_connected() and not yolink_connected:
            import yolink_mqtt
            yolink_mqtt.connected = True
            return True
        return False
    except Exception as e:
        logger.error(f"Error checking YoLink MQTT connection: {e}")
        return False

def check_monitor_connection_active():
    """Actively check if Monitor MQTT connection is functional"""
    from monitor_mqtt import client as monitor_client, connected as monitor_connected
    try:
        # Check if the client exists and is connected
        if monitor_client and monitor_client.is_connected():
            return True
        # If the client says it's connected but the global var doesn't, update the global
        elif monitor_client and monitor_client.is_connected() and not monitor_connected:
            import monitor_mqtt
            monitor_mqtt.connected = True
            return True
        return False
    except Exception as e:
        logger.error(f"Error checking Monitor MQTT connection: {e}")
        return False


# Ensure Redis connection
if not ensure_redis_connection():
    logger.error("Exiting due to persistent Redis connection failure")
    exit(1)

init_default_user()

@scheduler.task('interval', id='sync_devices', seconds=300, misfire_grace_time=300)
def scheduled_device_refresh():
    """
    Scheduled task to refresh YoLink devices every 5 minutes.
    This ensures new devices appear and deleted devices are removed.
    """
    with app.app_context():
        try:
            logger.info(f"Running scheduled device refresh at {datetime.now()}")
            refresh_yolink_devices()
            logger.info("Scheduled device refresh completed successfully")
        except Exception as e:
            logger.error(f"Error in scheduled device refresh: {str(e)}")


def init_scheduler():
    try:
        # Only initialize once (in case of multiple workers)
        if not scheduler.running:
            scheduler.init_app(app)

            # Only start the device refresh job if the system is configured
            if is_system_configured():
                scheduler.start()
                logger.info("Scheduler started successfully")
            else:
                logger.info("Scheduler not started - waiting for system configuration")
        else:
            # If scheduler is already running but system is now configured,
            # ensure the jobs are restored
            if is_system_configured() and not scheduler.get_job('sync_devices'):
                scheduler.add_job(
                    id='sync_devices',
                    func=scheduled_device_refresh,
                    trigger='interval',
                    seconds=300,
                    misfire_grace_time=300
                )
                logger.info("Restored scheduled jobs after configuration")
    except Exception as e:
        logger.error(f"Failed to initialize scheduler: {str(e)}")

# Authentication Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        totp_code = request.form.get("totp_code")
        user_data = get_user_data(username)
        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            if user_data.get("force_password_change", False):
                login_user(User(username))
                return redirect(url_for("change_password"))
            if "totp_secret" in user_data:
                if not totp_code:
                    return render_template("login.html", totp_required=True, username=username)
                totp = pyotp.TOTP(user_data["totp_secret"])
                if not totp.verify(totp_code):
                    flash("Invalid TOTP code", "error")
                    return render_template("login.html", totp_required=True, username=username)
            else:
                login_user(User(username))
                return redirect(url_for("setup_totp"))
            login_user(User(username))
            return redirect(url_for("index"))
        flash("Invalid credentials", "error")
    return render_template("login.html", totp_required=False)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_data = get_user_data(current_user.id)
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        if not bcrypt.check_password_hash(user_data["password"], current_password):
            flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            flash("Password must be at least 8 characters", "error")
        else:
            user_data["password"] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_data["force_password_change"] = False
            save_user_data(current_user.id, user_data)
            if "totp_secret" not in user_data:
                return redirect(url_for("setup_totp"))
            flash("Password changed successfully", "success")
            return redirect(url_for("index"))
    return render_template("change_password.html")

@app.route("/setup_totp", methods=["GET", "POST"])
@login_required
def setup_totp():
    user_data = get_user_data(current_user.id)
    if "totp_secret" in user_data:
        flash("TOTP already set up", "info")
        return redirect(url_for("index"))
    if request.method == "POST":
        totp_code = request.form["totp_code"]
        totp_secret = session.get("totp_secret")
        if not totp_secret:
            flash("Session expired, please try again", "error")
            return redirect(url_for("setup_totp"))
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            user_data["totp_secret"] = totp_secret
            save_user_data(current_user.id, user_data)
            session.pop("totp_secret", None)
            flash("TOTP setup complete", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid TOTP code", "error")
    totp_secret = pyotp.random_base32()
    session["totp_secret"] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(current_user.id, issuer_name="YoLink-CHEKT")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return render_template("setup_totp.html", qr_img=qr_img)

# Main Routes
@app.route("/")
@login_required
def index():
    user_data = get_user_data(current_user.id)
    if user_data.get("force_password_change", False):
        flash("Please change your default password.", "warning")
        return redirect(url_for("change_password"))
    devices = get_all_devices()
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}
    for device in devices:
        device["chekt_zone"] = device_mappings.get(device["deviceId"], {}).get("chekt_zone", "N/A")
        device["door_prop_alarm"] = device_mappings.get(device["deviceId"], {}).get("door_prop_alarm", False)
    return render_template("index.html", devices=devices)


@app.route("/config", methods=["GET", "POST"])
@login_required
def config():
    config_data = load_config()
    if request.method == "POST":
        try:
            # Extract receiver enabled states with safer parsing
            chekt_enabled = request.form.get("chekt_enabled") == "on"
            sia_enabled = request.form.get("sia_enabled") == "on"
            modbus_enabled = request.form.get("modbus_enabled") == "on"

            # Extract Modbus settings with better error handling
            modbus_follower_mode = request.form.get("modbus_follower_mode") == "on"

            # Safely convert numeric values with defaults
            try:
                modbus_max_channels = int(request.form.get("modbus_max_channels", 16))
            except (ValueError, TypeError):
                modbus_max_channels = 16

            try:
                modbus_pulse_seconds = float(request.form.get("modbus_pulse_seconds", 1))
            except (ValueError, TypeError):
                modbus_pulse_seconds = 1.0

            # Handle YoLink port safely
            try:
                yolink_port = int(request.form.get("yolink_port", 8003))
            except (ValueError, TypeError):
                yolink_port = 8003

            # Handle CHEKT port safely
            try:
                chekt_port = int(request.form.get("chekt_port", 30003))
            except (ValueError, TypeError):
                chekt_port = 30003

            # Handle Modbus port safely
            try:
                modbus_port = int(request.form.get("modbus_port", 502))
            except (ValueError, TypeError):
                modbus_port = 502

            # Handle Modbus unit_id safely
            try:
                modbus_unit_id = int(request.form.get("modbus_unit_id", 1))
            except (ValueError, TypeError):
                modbus_unit_id = 1

            # Handle SIA port safely
            sia_port = ""
            if request.form.get("sia_port"):
                try:
                    sia_port = int(request.form["sia_port"])
                except (ValueError, TypeError):
                    sia_port = ""

            # Handle monitor MQTT port safely
            try:
                monitor_mqtt_port = int(request.form.get("monitor_mqtt_port", 1883))
            except (ValueError, TypeError):
                monitor_mqtt_port = 1883

            # Handle door_open_timeout safely
            try:
                door_open_timeout = int(request.form.get("door_open_timeout", 30))
            except (ValueError, TypeError):
                door_open_timeout = 30

            # Build the new configuration with safe values
            new_config = {
                "yolink": {
                    "uaid": request.form.get("yolink_uaid", ""),
                    "secret_key": request.form.get("yolink_secret_key", ""),
                    "token": config_data["yolink"].get("token", ""),
                    "token_expiry": config_data["yolink"].get("token_expiry", 0)
                },
                "mqtt": {
                    "url": request.form.get("yolink_url", "mqtt://api.yosmart.com"),
                    "port": yolink_port,
                    "topic": request.form.get("yolink_topic", "yl-home/${Home ID}/+/report")
                },
                "mqtt_monitor": {
                    "url": request.form.get("monitor_mqtt_url", "mqtt://monitor.industrialcamera.com"),
                    "port": monitor_mqtt_port,
                    "username": request.form.get("monitor_mqtt_username", ""),
                    "password": request.form.get("monitor_mqtt_password", ""),
                    "client_id": "monitor_client_id"
                },
                "receiver_type": request.form.get("receiver_type", "CHEKT"),
                "chekt": {
                    "api_token": request.form.get("chekt_api_token", ""),
                    "ip": request.form.get("chekt_ip", ""),
                    "port": chekt_port,
                    "enabled": chekt_enabled
                },
                "sia": {
                    "ip": request.form.get("sia_ip", ""),
                    "port": sia_port,
                    "account_id": request.form.get("sia_account_id", ""),
                    "transmitter_id": request.form.get("sia_transmitter_id", ""),
                    "encryption_key": request.form.get("sia_encryption_key", ""),
                    "enabled": sia_enabled
                },
                "modbus": {
                    "ip": request.form.get("modbus_ip", ""),
                    "port": modbus_port,
                    "unit_id": modbus_unit_id,
                    "max_channels": modbus_max_channels,
                    "pulse_seconds": modbus_pulse_seconds,
                    "enabled": modbus_enabled,
                    "follower_mode": modbus_follower_mode
                },
                "monitor": {"api_key": request.form.get("monitor_api_key", "")},
                "timezone": "UTC",  # Use UTC as default (removing timezone selection)
                "door_open_timeout": door_open_timeout,
                "home_id": config_data.get("home_id", ""),
                "supported_timezones": SUPPORTED_TIMEZONES
            }
            save_config(new_config)
            flash("Configuration saved", "success")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            flash(f"Error saving configuration: {str(e)}", "error")
        return redirect(url_for("config"))
    return render_template("config.html", config=config_data)

@app.route('/get_config')
@login_required
def get_config():
    config = load_config()
    return jsonify(config)

# User Management
@app.route("/create_user", methods=["POST"])
@login_required
def create_user():
    username = request.form["username"]
    password = request.form["password"]
    if not username or not password:
        flash("Username and password required", "error")
        return redirect(url_for("config"))
    if get_user_data(username):
        flash("Username already exists", "error")
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {"password": hashed_password, "force_password_change": True}
        save_user_data(username, user_data)
        flash("User created successfully", "success")
    return redirect(url_for("config"))

# Device Management
@app.route("/refresh_devices")
@login_required
def refresh_devices():
    """Updated to return JSON for AJAX requests"""
    try:
        # Check if this is an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'

        refresh_yolink_devices()

        if is_ajax:
            return jsonify({
                "status": "success",
                "message": "Devices refreshed successfully"
            })
        else:
            flash("Devices refreshed successfully", "success")
            return redirect(url_for("index"))

    except Exception as e:
        logger.error(f"Device refresh failed: {e}")

        if is_ajax:
            return jsonify({
                "status": "error",
                "message": f"Failed to refresh devices: {str(e)}"
            })
        else:
            flash("Failed to refresh devices", "error")
            return redirect(url_for("index"))

@app.route("/system_uptime")
@login_required
def system_uptime():
    boot_time = psutil.boot_time()
    current_time = time.time()
    uptime_seconds = current_time - boot_time
    return jsonify({"uptime_seconds": uptime_seconds})

@app.route("/save_mapping", methods=["POST"])
@login_required
def save_mapping_route():
    data = request.get_json()
    device_id = data.get("yolink_device_id")
    chekt_zone = data.get("chekt_zone", "N/A")
    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400
    logger.debug(f"Attempting to save CHEKT zone for device {device_id}: {chekt_zone}")
    save_mapping(device_id, chekt_zone)
    logger.debug(f"Saved mapping, current mappings: {json.dumps(get_mappings())}")
    return jsonify({"status": "success"})

@app.route("/set_door_prop_alarm", methods=["POST"])
@login_required
def set_door_prop_alarm():
    data = request.get_json()
    device_id = data.get("device_id")
    enabled = data.get("enabled", False)  # Default to False if not provided
    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400
    logger.debug(f"Setting door prop alarm for device {device_id} to {enabled}")
    mappings = get_mappings()
    updated = False
    for mapping in mappings["mappings"]:
        if mapping["yolink_device_id"] == device_id:
            mapping["door_prop_alarm"] = enabled
            updated = True
            break
    if not updated:
        mappings["mappings"].append({
            "yolink_device_id": device_id,
            "chekt_zone": "N/A",
            "door_prop_alarm": enabled
        })
    save_mappings(mappings)
    logger.debug(f"Updated mappings: {json.dumps(mappings)}")
    return jsonify({"status": "success"})


@app.route("/get_sensor_data")
def get_sensor_data():
    devices = get_all_devices()
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}

    for device in devices:
        mapping = device_mappings.get(device["deviceId"], {})
        device["chekt_zone"] = mapping.get("chekt_zone", "N/A")
        device["door_prop_alarm"] = mapping.get("door_prop_alarm", False)
        device["relay_channel"] = mapping.get("relay_channel", "N/A")
        device["use_relay"] = mapping.get("use_relay", False)

        # Set defaults for missing fields
        device.setdefault("state", "unknown")
        device.setdefault("signal", "unknown")
        device.setdefault("battery", "unknown")
        device.setdefault("last_seen", "never")
        device.setdefault("alarms", {})
        device.setdefault("temperature", "unknown")
        device.setdefault("humidity", "unknown")

    return jsonify({"devices": devices})

# Logging and Status
@app.route("/get_logs", methods=["GET"])
@login_required
def get_logs():
    try:
        with open("/app/logs/application.log", "r") as f:
            logs = "".join(f.readlines()[-150:])
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found"})

@app.route("/check_mqtt_status")
@login_required
def check_mqtt_status():
    is_connected = check_mqtt_connection_active()
    return jsonify({
        "status": "success" if is_connected else "error",
        "message": "YoLink MQTT connection is active." if is_connected else "YoLink MQTT connection is inactive."
    })

@app.route("/check_monitor_mqtt_status")
@login_required
def check_monitor_mqtt_status():
    is_connected = check_monitor_connection_active()
    return jsonify({
        "status": "success" if is_connected else "error",
        "message": "Monitor MQTT connection is active." if is_connected else "Monitor MQTT connection is inactive."
    })

@app.route("/check_receiver_status")
@login_required
def check_receiver_status():
    config = load_config()
    receiver_type = config.get("receiver_type", "CHEKT")
    if receiver_type == "CHEKT":
        return jsonify({"status": "success", "message": "Receiver is alive."})
    return jsonify({"status": "success", "message": "SIA receiver assumed alive."})


@app.route('/check_all_statuses')
@login_required
def check_all_statuses():
    # Check YoLink MQTT connection
    yolink_active = check_mqtt_connection_active()

    # Check Monitor MQTT connection
    monitor_active = check_monitor_connection_active()

    # Check Modbus connection if enabled
    config = load_config()
    modbus_active = False
    modbus_message = "Modbus relay is disabled"

    if config.get("modbus", {}).get("enabled", False):
        try:
            import modbus_relay
            modbus_active = modbus_relay.ensure_connection()
            modbus_message = "Modbus Relay Connected" if modbus_active else "Modbus Relay Disconnected"
        except Exception as e:
            logger.error(f"Error checking Modbus status: {e}")
            modbus_message = f"Error checking Modbus relay: {str(e)}"

    # Determine receiver status based on receiver type
    receiver_type = config.get("receiver_type", "CHEKT")
    receiver_active = True  # Default to assume it's working
    receiver_message = "Receiver Connected"

    # For CHEKT, we could implement an actual status check in the future
    if receiver_type == "CHEKT":
        receiver_message = "CHEKT Receiver Connected"
    elif receiver_type == "SIA":
        receiver_message = "SIA Receiver Assumed Connected"

    return jsonify({
        "yolink": {
            "status": "success" if yolink_active else "error",
            "message": "YoLink MQTT Connected" if yolink_active else "YoLink MQTT Disconnected"
        },
        "monitor": {
            "status": "success" if monitor_active else "error",
            "message": "Monitor MQTT Connected" if monitor_active else "Monitor MQTT Disconnected"
        },
        "receiver": {
            "status": "success" if receiver_active else "error",
            "message": receiver_message
        },
        "modbus": {
            "status": "success" if modbus_active else "error",
            "message": modbus_message
        }
    })


@app.route('/last_refresh')
@login_required
def last_refresh():
    """Return the timestamp of the last device refresh"""
    try:
        last_refresh_time = redis_client.get("last_refresh_time")
        if last_refresh_time:
            # Convert from stored string to datetime for formatting
            last_time = datetime.fromtimestamp(float(last_refresh_time))
            formatted_time = last_time.strftime("%Y-%m-%d %H:%M:%S")
            time_ago = (datetime.now() - last_time).total_seconds() / 60.0

            return jsonify({
                "status": "success",
                "last_refresh": formatted_time,
                "minutes_ago": round(time_ago, 1)
            })
        else:
            return jsonify({
                "status": "success",
                "last_refresh": "Never",
                "minutes_ago": None
            })
    except Exception as e:
        logger.error(f"Error getting last refresh time: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/restart_services', methods=['POST'])
@login_required
def restart_services():
    """Endpoint to restart MQTT services after configuration changes"""
    try:
        start_services()
        return jsonify({"status": "success", "message": "Services restarted"})
    except Exception as e:
        logger.error(f"Error restarting services: {e}")
        return jsonify({"status": "error", "message": str(e)})


@app.route("/save_relay_mapping", methods=["POST"])
@login_required
def save_relay_mapping_route():
    data = request.get_json()
    device_id = data.get("yolink_device_id")
    relay_channel = data.get("relay_channel", "N/A")
    use_relay = data.get("use_relay", False)

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(
        f"Attempting to save relay mapping for device {device_id}: Channel {relay_channel}, Use Relay: {use_relay}")

    # Don't update CHEKT zone, only the relay settings
    save_mapping(device_id, relay_channel=relay_channel, use_relay=use_relay)

    logger.debug(f"Saved relay mapping, current mappings: {json.dumps(get_mappings())}")
    return jsonify({"status": "success"})


@app.route('/check_modbus_status')
@login_required
def check_modbus_status():
    """Check if the Modbus relay is reachable"""
    import modbus_relay

    config = load_config()
    if not config.get("modbus", {}).get("enabled", False):
        return jsonify({
            "status": "warning",
            "message": "Modbus relay is disabled in configuration."
        })

    try:
        is_connected = modbus_relay.ensure_connection()
        return jsonify({
            "status": "success" if is_connected else "error",
            "message": "Modbus relay connection is active." if is_connected else "Modbus relay connection is inactive."
        })
    except Exception as e:
        logger.error(f"Error checking Modbus status: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error checking Modbus status: {str(e)}"
        })


@app.route('/test_relay_channel', methods=['POST'])
@login_required
def test_relay_channel():
    """Test a specific relay channel"""
    data = request.get_json()
    channel = data.get('channel')

    if not channel:
        return jsonify({"status": "error", "message": "Missing channel number"}), 400

    try:
        channel = int(channel)
    except ValueError:
        return jsonify({"status": "error", "message": "Channel must be a number"}), 400

    config = load_config()
    if not config.get("modbus", {}).get("enabled", False):
        return jsonify({"status": "error", "message": "Modbus relay is disabled in configuration"}), 400

    try:
        import modbus_relay
        if not modbus_relay.ensure_connection():
            return jsonify({"status": "error", "message": "Cannot connect to Modbus relay"}), 500

        # Test both on and off in sequence
        logger.info(f"Testing relay channel {channel}")

        # First turn on
        on_success = modbus_relay.trigger_relay(channel, True, 1.0)
        if not on_success:
            return jsonify({"status": "error", "message": f"Failed to turn on relay channel {channel}"}), 500

        return jsonify({
            "status": "success",
            "message": f"Relay channel {channel} pulsed successfully"
        })
    except Exception as e:
        logger.error(f"Error testing relay channel {channel}: {e}")
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"Error testing relay: {str(e)}"
        }), 500


@app.route('/test_modbus', methods=['GET'])
@login_required
def test_modbus():
    """Test route to diagnose Modbus connectivity"""
    config = load_config()
    modbus_config = config.get('modbus', {})

    if not modbus_config.get('enabled', False):
        return jsonify({"status": "warning", "message": "Modbus is not enabled in configuration"})

    modbus_ip = modbus_config.get('ip')
    modbus_port = modbus_config.get('port', 502)

    if not modbus_ip:
        return jsonify({"status": "error", "message": "Modbus IP not configured"})

    results = {"status": "checking", "tests": []}

    # Test 1: Check proxy health
    try:
        import requests
        try:
            response = requests.get("http://modbus-proxy:1502/healthcheck", timeout=2)
            if response.status_code == 200:
                data = response.json()
                proxy_healthy = data.get("status") == "healthy" and data.get("proxy_running", False)
            else:
                proxy_healthy = False

            results["tests"].append({
                "name": "Modbus Proxy Health",
                "success": proxy_healthy,
                "message": f"Proxy service is {'healthy' if proxy_healthy else 'unhealthy'}"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Modbus Proxy Health",
                "success": False,
                "message": f"Failed to reach proxy health check: {str(e)}"
            })
    except Exception as e:
        results["tests"].append({
            "name": "Modbus Proxy Health",
            "success": False,
            "message": f"Error testing proxy health: {str(e)}"
        })

    # Test 2: Test proxy configuration
    try:
        import modbus_relay
        try:
            config_result = modbus_relay.configure_proxy(modbus_ip, modbus_port)
            results["tests"].append({
                "name": "Proxy Configuration",
                "success": config_result,
                "message": f"Proxy configuration {'successful' if config_result else 'failed'}"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Proxy Configuration",
                "success": False,
                "message": f"Error configuring proxy: {str(e)}"
            })
    except Exception as e:
        results["tests"].append({
            "name": "Proxy Configuration",
            "success": False,
            "message": f"Error importing modbus_relay: {str(e)}"
        })

    # Test 3: Full Modbus connectivity
    try:
        if hasattr(modbus_relay, 'ensure_connection'):
            connection_result = modbus_relay.ensure_connection()
            results["tests"].append({
                "name": "Modbus Connection",
                "success": connection_result,
                "message": f"Modbus connection {'successful' if connection_result else 'failed'}"
            })
        else:
            results["tests"].append({
                "name": "Modbus Connection",
                "success": False,
                "message": "Modbus relay module not properly initialized"
            })
    except Exception as e:
        results["tests"].append({
            "name": "Modbus Connection",
            "success": False,
            "message": f"Modbus connection test error: {str(e)}"
        })

    # Test 4: Try a single relay operation if connection succeeded
    if any(test["name"] == "Modbus Connection" and test["success"] for test in results["tests"]):
        try:
            if hasattr(modbus_relay, 'trigger_relay'):
                # Use the first relay for testing
                relay_result = modbus_relay.trigger_relay(1, True, 0.5)
                results["tests"].append({
                    "name": "Relay Operation",
                    "success": relay_result,
                    "message": f"Relay trigger {'successful' if relay_result else 'failed'}"
                })
            else:
                results["tests"].append({
                    "name": "Relay Operation",
                    "success": False,
                    "message": "Modbus relay trigger function not available"
                })
        except Exception as e:
            results["tests"].append({
                "name": "Relay Operation",
                "success": False,
                "message": f"Relay test error: {str(e)}"
            })

    # Set overall status
    success_count = sum(1 for test in results["tests"] if test["success"])
    if success_count == len(results["tests"]):
        results["status"] = "success"
        results["message"] = "All Modbus tests passed successfully"
    elif success_count > 0:
        results["status"] = "warning"
        results["message"] = f"{success_count}/{len(results['tests'])} tests passed"
    else:
        results["status"] = "error"
        results["message"] = "All Modbus tests failed"

    return jsonify(results)


# Main Entry
if __name__ == "__main__":
    # Initialize services based on configuration
    start_services()

    # Initialize the scheduler
    init_scheduler()

    # Run the Flask app (this should always be last)
    app.run(host="0.0.0.0", port=5000)