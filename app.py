"""
Yolink to CHEKT Integration - Version 1.3 (Refactored)
======================================================

Main application file for integrating Yolink smart sensors with the CHEKT alarm system
and Modbus relays via MQTT, with a web interface for management.
This version uses Quart’s before_serving and after_serving hooks to manage background
services and graceful shutdown.
"""

import os
import logging
import json
import base64
import io
import asyncio
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional
from quart import Quart, request, render_template, flash, redirect, url_for, session, jsonify
from quart_auth import QuartAuth, login_user, login_required, logout_user, current_user
from quart_bcrypt import Bcrypt
import pyotp
import qrcode
import psutil
from apscheduler.schedulers.async_ import AsyncScheduler
from redis.asyncio import Redis

# Import project modules
from config import load_config, save_config, get_user_data, save_user_data, SUPPORTED_TIMEZONES
from device_manager import refresh_yolink_devices, get_all_devices
from mappings import get_mappings, save_mapping, save_mappings
from yolink_mqtt import connected as yolink_connected, run_mqtt_client
from monitor_mqtt import connected as monitor_connected, run_monitor_mqtt, shutdown_monitor_mqtt
import modbus_relay
from db import ensure_redis_connection

# Logging Setup
handler = RotatingFileHandler("/app/logs/app.log", maxBytes=10*1024*1024, backupCount=5)
logging.basicConfig(
    level=logging.INFO,  # INFO in production, DEBUG for development
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Quart app
app = Quart(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set")
bcrypt = Bcrypt(app)

# Setup Quart-Auth (replacing Flask-Login for async support)
auth_manager = QuartAuth()
auth_manager.init_app(app)

# Scheduler for periodic tasks
scheduler = AsyncScheduler()

# Global Redis client (async)
redis_client = Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=0,
    decode_responses=True
)

# To hold background tasks so we can cancel them on shutdown
app.bg_tasks = []

# ----------------------- Authentication Helpers -----------------------

class User:
    """User class for authentication."""
    def __init__(self, username: str):
        self.auth_id = username

    @staticmethod
    async def load(username: str) -> Optional["User"]:
        if get_user_data(username):
            return User(username)
        return None

@auth_manager.user_loader
async def load_user(username: str) -> Optional[User]:
    return await User.load(username)


async def init_default_user() -> None:
    """Create a default admin user if no users exist."""
    from config import get_user_data, save_user_data
    from redis_manager import get_redis

    redis_client = await get_redis()
    keys = await redis_client.keys("user:*")
    if not keys:
        default_username = "admin"
        default_password = "admin123"
        hashed_password = await bcrypt.hashpw(default_password.encode('utf-8'))
        user_data = {"password": hashed_password.decode('utf-8'), "force_password_change": True}
        await save_user_data(default_username, user_data)
        logger.info("Created default admin user")

# ----------------------- Utility Functions -----------------------

async def check_mqtt_connection_active() -> Dict[str, Any]:
    """Actively check if YoLink MQTT connection is functional."""
    from yolink_mqtt import client as yolink_client
    try:
        if yolink_client and yolink_client.is_connected():
            return {"status": "success", "message": "YoLink MQTT connection is active."}
        return {"status": "error", "message": "YoLink MQTT connection is inactive."}
    except Exception as e:
        logger.error(f"Error checking YoLink MQTT connection: {e}")
        return {"status": "error", "message": f"Error checking YoLink MQTT: {str(e)}"}

async def check_monitor_connection_active() -> Dict[str, Any]:
    """Actively check if Monitor MQTT connection is functional."""
    from monitor_mqtt import client as monitor_client
    try:
        if monitor_client and monitor_client.is_connected():
            return {"status": "success", "message": "Monitor MQTT connection is active."}
        return {"status": "error", "message": "Monitor MQTT connection is inactive."}
    except Exception as e:
        logger.error(f"Error checking Monitor MQTT connection: {e}")
        return {"status": "error", "message": f"Error checking Monitor MQTT: {str(e)}"}

def is_system_configured() -> bool:
    """Check if the system has necessary credentials configured."""
    config = load_config()  # Synchronous call here is acceptable in context
    yolink_configured = (
        config.get("yolink", {}).get("uaid") and
        config.get("yolink", {}).get("secret_key")
    )
    monitor_configured = config.get("mqtt_monitor", {}).get("url")
    receiver_configured = (
        config.get("chekt", {}).get("enabled", True) or
        config.get("sia", {}).get("enabled", False) or
        config.get("modbus", {}).get("enabled", False)
    )
    return yolink_configured and monitor_configured and receiver_configured

# ----------------------- Background Startup & Shutdown -----------------------

@app.before_serving
async def startup():
    """Startup tasks to run before the Quart server starts serving."""
    # Initialize Redis connection manager
    from redis_manager import get_redis, ensure_connection

    # Ensure Redis connection
    if not await ensure_connection(max_retries=5, backoff_base=1.5):
        logger.error("Exiting due to persistent Redis connection failure")
        raise SystemExit(1)

    # Initialize the default admin user
    await init_default_user()

    # Start background services if system is configured
    if is_system_configured():
        logger.info("System configured, starting background services")

        # Start YoLink MQTT client
        from yolink_mqtt import run_mqtt_client, shutdown_yolink_mqtt
        task_yolink = asyncio.create_task(run_mqtt_client())
        app.bg_tasks.append(task_yolink)
        app.ctx.shutdown_yolink = shutdown_yolink_mqtt  # Store the shutdown function

        # Start Monitor MQTT client
        from monitor_mqtt import run_monitor_mqtt, shutdown_monitor_mqtt
        task_monitor = asyncio.create_task(run_monitor_mqtt())
        app.bg_tasks.append(task_monitor)
        app.ctx.shutdown_monitor = shutdown_monitor_mqtt  # Store the shutdown function

        # Initialize Modbus relay connection
        import modbus_relay
        task_modbus = asyncio.create_task(modbus_relay.initialize())
        app.bg_tasks.append(task_modbus)
        app.ctx.shutdown_modbus = modbus_relay.shutdown_modbus  # Store the shutdown function
    else:
        logger.warning("System not fully configured; background services not started")
        app.ctx.shutdown_yolink = None
        app.ctx.shutdown_monitor = None
        app.ctx.shutdown_modbus = None

    # Start scheduler for periodic tasks
    try:
        await scheduler.start()
        logger.info("Scheduler started successfully")
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")


@app.after_serving
async def shutdown():
    """Shutdown tasks to run after the Quart server stops serving."""
    logger.info("Initiating graceful shutdown of background services")

    # Call module-specific shutdown functions first
    shutdown_functions = [
        (app.ctx.shutdown_modbus, "Modbus relay"),
        (app.ctx.shutdown_monitor, "Monitor MQTT"),
        (app.ctx.shutdown_yolink, "YoLink MQTT")
    ]

    for shutdown_fn, name in shutdown_functions:
        if shutdown_fn:
            try:
                if asyncio.iscoroutinefunction(shutdown_fn):
                    await shutdown_fn()
                else:
                    shutdown_fn()
                logger.info(f"{name} shutdown signal sent successfully")
            except Exception as e:
                logger.error(f"Error sending shutdown signal to {name}: {e}")

    # Cancel background tasks
    pending_tasks = []
    for task in app.bg_tasks:
        if not task.done():
            task.cancel()
            pending_tasks.append(task)

    if pending_tasks:
        logger.info(f"Waiting for {len(pending_tasks)} tasks to complete...")
        try:
            await asyncio.wait(pending_tasks, timeout=10)
            # Check if any tasks are still pending
            still_pending = [t for t in pending_tasks if not t.done()]
            if still_pending:
                logger.warning(f"{len(still_pending)} tasks did not complete within timeout")
        except asyncio.CancelledError:
            logger.info("Background tasks cancelled successfully")
        except Exception as e:
            logger.error(f"Error during task cancellation: {e}")

    # Shutdown scheduler
    try:
        await scheduler.shutdown(wait=False)
        logger.info("Scheduler shutdown successfully")
    except Exception as e:
        logger.error(f"Error shutting down scheduler: {e}")

    # Close Redis connection
    try:
        from redis_manager import close as close_redis
        await close_redis()
    except Exception as e:
        logger.error(f"Error closing Redis client: {e}")

    logger.info("Application shutdown complete")

# ----------------------- Authentication Routes -----------------------

@app.route("/login", methods=["GET", "POST"])
async def login():
    if request.method == "POST":
        form = await request.form
        username = form["username"]
        password = form["password"]
        totp_code = form.get("totp_code")
        user_data = get_user_data(username)

        if not user_data or not await bcrypt.checkpw(password.encode('utf-8'), user_data["password"].encode('utf-8')):
            await flash("Invalid credentials", "error")
            return await render_template("login.html", totp_required=False)

        if user_data.get("force_password_change", False):
            login_user(username)
            return redirect(url_for("change_password"))

        if "totp_secret" in user_data:
            if not totp_code:
                return await render_template("login.html", totp_required=True, username=username)
            totp = pyotp.TOTP(user_data["totp_secret"])
            if not totp.verify(totp_code):
                await flash("Invalid TOTP code", "error")
                return await render_template("login.html", totp_required=True, username=username)
        else:
            login_user(username)
            return redirect(url_for("setup_totp"))

        login_user(username)
        return redirect(url_for("index"))

    return await render_template("login.html", totp_required=False)

@app.route("/logout")
@login_required
async def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
async def change_password():
    user_data = get_user_data(current_user.auth_id)
    if request.method == "POST":
        form = await request.form
        current_password = form["current_password"]
        new_password = form["new_password"]
        confirm_password = form["confirm_password"]

        if not await bcrypt.checkpw(current_password.encode('utf-8'), user_data["password"].encode('utf-8')):
            await flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            await flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            await flash("Password must be at least 8 characters", "error")
        else:
            user_data["password"] = (await bcrypt.hashpw(new_password.encode('utf-8'))).decode('utf-8')
            user_data["force_password_change"] = False
            save_user_data(current_user.auth_id, user_data)
            if "totp_secret" not in user_data:
                return redirect(url_for("setup_totp"))
            await flash("Password changed successfully", "success")
            return redirect(url_for("index"))

    return await render_template("change_password.html")

@app.route("/setup_totp", methods=["GET", "POST"])
@login_required
async def setup_totp():
    user_data = get_user_data(current_user.auth_id)
    if "totp_secret" in user_data:
        await flash("TOTP already set up", "info")
        return redirect(url_for("index"))

    if request.method == "POST":
        form = await request.form
        totp_code = form["totp_code"]
        totp_secret = session.get("totp_secret")
        if not totp_secret:
            await flash("Session expired, please try again", "error")
            return redirect(url_for("setup_totp"))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            user_data["totp_secret"] = totp_secret
            save_user_data(current_user.auth_id, user_data)
            session.pop("totp_secret", None)
            await flash("TOTP setup complete", "success")
            return redirect(url_for("index"))
        else:
            await flash("Invalid TOTP code", "error")

    totp_secret = pyotp.random_base32()
    session["totp_secret"] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(current_user.auth_id, issuer_name="YoLink-CHEKT")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return await render_template("setup_totp.html", qr_img=qr_img)

# ----------------------- Main Routes -----------------------

@app.route("/")
@login_required
async def index():
    user_data = get_user_data(current_user.auth_id)
    if user_data.get("force_password_change", False):
        await flash("Please change your default password.", "warning")
        return redirect(url_for("change_password"))

    devices = await get_all_devices()
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}
    for device in devices:
        mapping = device_mappings.get(device["deviceId"], {})
        device["chekt_zone"] = mapping.get("chekt_zone", "N/A")
        device["door_prop_alarm"] = mapping.get("door_prop_alarm", False)

    return await render_template("index.html", devices=devices)

@app.route("/config", methods=["GET", "POST"])
@login_required
async def config():
    config_data = load_config()
    if request.method == "POST":
        try:
            form = await request.form
            if not form.get("yolink_uaid") or not form.get("yolink_secret_key"):
                await flash("YoLink UAID and Secret Key are required", "error")
                return redirect(url_for("config"))

            chekt_enabled = form.get("chekt_enabled") == "on"
            sia_enabled = form.get("sia_enabled") == "on"
            modbus_enabled = form.get("modbus_enabled") == "on"
            modbus_follower_mode = form.get("modbus_follower_mode") == "on"

            modbus_max_channels = int(form.get("modbus_max_channels", 16)) if form.get("modbus_max_channels") else 16
            modbus_pulse_seconds = float(form.get("modbus_pulse_seconds", 1)) if form.get("modbus_pulse_seconds") else 1.0
            yolink_port = int(form.get("yolink_port", 8003)) if form.get("yolink_port") else 8003
            chekt_port = int(form.get("chekt_port", 30003)) if form.get("chekt_port") else 30003
            modbus_port = int(form.get("modbus_port", 502)) if form.get("modbus_port") else 502
            modbus_unit_id = int(form.get("modbus_unit_id", 1)) if form.get("modbus_unit_id") else 1
            sia_port = int(form.get("sia_port", "")) if form.get("sia_port") else ""
            monitor_mqtt_port = int(form.get("monitor_mqtt_port", 1883)) if form.get("monitor_mqtt_port") else 1883
            door_open_timeout = int(form.get("door_open_timeout", 30)) if form.get("door_open_timeout") else 30

            new_config = {
                "yolink": {
                    "uaid": form.get("yolink_uaid", ""),
                    "secret_key": form.get("yolink_secret_key", ""),
                    "token": config_data["yolink"].get("token", ""),
                    "token_expiry": config_data["yolink"].get("token_expiry", 0)
                },
                "mqtt": {
                    "url": form.get("yolink_url", "mqtt://api.yosmart.com"),
                    "port": yolink_port,
                    "topic": form.get("yolink_topic", "yl-home/${Home ID}/+/report")
                },
                "mqtt_monitor": {
                    "url": form.get("monitor_mqtt_url", "mqtt://monitor.industrialcamera.com"),
                    "port": monitor_mqtt_port,
                    "username": form.get("monitor_mqtt_username", ""),
                    "password": form.get("monitor_mqtt_password", ""),
                    "client_id": "monitor_client_id"
                },
                "receiver_type": form.get("receiver_type", "CHEKT"),
                "chekt": {
                    "api_token": form.get("chekt_api_token", ""),
                    "ip": form.get("chekt_ip", ""),
                    "port": chekt_port,
                    "enabled": chekt_enabled
                },
                "sia": {
                    "ip": form.get("sia_ip", ""),
                    "port": sia_port,
                    "account_id": form.get("sia_account_id", ""),
                    "transmitter_id": form.get("sia_transmitter_id", ""),
                    "encryption_key": form.get("sia_encryption_key", ""),
                    "enabled": sia_enabled
                },
                "modbus": {
                    "ip": form.get("modbus_ip", ""),
                    "port": modbus_port,
                    "unit_id": modbus_unit_id,
                    "max_channels": modbus_max_channels,
                    "pulse_seconds": modbus_pulse_seconds,
                    "enabled": modbus_enabled,
                    "follower_mode": modbus_follower_mode
                },
                "monitor": {"api_key": form.get("monitor_api_key", "")},
                "timezone": "UTC",
                "door_open_timeout": door_open_timeout,
                "home_id": config_data.get("home_id", ""),
                "supported_timezones": SUPPORTED_TIMEZONES
            }
            save_config(new_config)
            await flash("Configuration saved", "success")
            # Restart services based on new configuration
            # (In production, you might restart background tasks here if necessary)
        except ValueError as e:
            logger.error(f"Invalid input in configuration: {str(e)}")
            await flash(f"Invalid input: {str(e)}", "error")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            await flash(f"Error saving configuration: {str(e)}", "error")
        return redirect(url_for("config"))

    return await render_template("config.html", config=config_data)

@app.route('/get_config')
@login_required
async def get_config():
    config = load_config()
    return jsonify(config)

# ----------------------- User Management -----------------------

@app.route("/create_user", methods=["POST"])
@login_required
async def create_user():
    form = await request.form
    username = form["username"]
    password = form["password"]

    if not username or not password:
        await flash("Username and password required", "error")
        return redirect(url_for("config"))

    if len(password) < 8:
        await flash("Password must be at least 8 characters", "error")
        return redirect(url_for("config"))

    if get_user_data(username):
        await flash("Username already exists", "error")
    else:
        hashed_password = (await bcrypt.hashpw(password.encode('utf-8'))).decode('utf-8')
        user_data = {"password": hashed_password, "force_password_change": True}
        save_user_data(username, user_data)
        await flash("User created successfully", "success")
    return redirect(url_for("config"))

# ----------------------- Device Management -----------------------

@app.route("/refresh_devices")
@login_required
async def refresh_devices():
    try:
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
        await refresh_yolink_devices()

        if is_ajax:
            return jsonify({"status": "success", "message": "Devices refreshed successfully"})
        else:
            await flash("Devices refreshed successfully", "success")
            return redirect(url_for("index"))

    except Exception as e:
        logger.error(f"Device refresh failed: {e}")
        if is_ajax:
            return jsonify({"status": "error", "message": f"Failed to refresh devices: {str(e)}"}), 500
        else:
            await flash("Failed to refresh devices", "error")
            return redirect(url_for("index"))

@app.route("/system_uptime")
@login_required
async def system_uptime():
    boot_time = psutil.boot_time()
    current_time = datetime.now().timestamp()
    uptime_seconds = current_time - boot_time
    return jsonify({"uptime_seconds": uptime_seconds})

@app.route("/save_mapping", methods=["POST"])
@login_required
async def save_mapping_route():
    data = await request.get_json()
    device_id = data.get("yolink_device_id")
    chekt_zone = data.get("chekt_zone", "N/A")

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(f"Saving CHEKT zone for device {device_id}: {chekt_zone}")
    save_mapping(device_id, chekt_zone)
    return jsonify({"status": "success"})

@app.route("/set_door_prop_alarm", methods=["POST"])
@login_required
async def set_door_prop_alarm():
    data = await request.get_json()
    device_id = data.get("device_id")
    enabled = data.get("enabled", False)

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
    return jsonify({"status": "success"})

@app.route("/get_sensor_data")
@login_required
async def get_sensor_data():
    devices = await get_all_devices()
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}

    for device in devices:
        mapping = device_mappings.get(device["deviceId"], {})
        device["chekt_zone"] = mapping.get("chekt_zone", "N/A")
        device["door_prop_alarm"] = mapping.get("door_prop_alarm", False)
        device["relay_channel"] = mapping.get("relay_channel", "N/A")
        device["use_relay"] = mapping.get("use_relay", False)
        device.setdefault("state", "unknown")
        device.setdefault("signal", "unknown")
        device.setdefault("battery", "unknown")
        device.setdefault("last_seen", "never")
        device.setdefault("alarms", {})
        device.setdefault("temperature", "unknown")
        device.setdefault("humidity", "unknown")

    return jsonify({"devices": devices})

# ----------------------- Logging and Status -----------------------

@app.route("/get_logs", methods=["GET"])
@login_required
async def get_logs():
    try:
        with open("/app/logs/app.log", "r") as f:
            logs = "".join(f.readlines()[-50:])
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found"}), 404
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return jsonify({"status": "error", "message": "Error reading logs"}), 500

@app.route("/check_mqtt_status")
@login_required
async def check_mqtt_status():
    return jsonify(await check_mqtt_connection_active())

@app.route("/check_monitor_mqtt_status")
@login_required
async def check_monitor_mqtt_status():
    return jsonify(await check_monitor_connection_active())

@app.route("/check_receiver_status")
@login_required
async def check_receiver_status():
    config = load_config()
    receiver_type = config.get("receiver_type", "CHEKT")
    if receiver_type == "CHEKT":
        return jsonify({"status": "success", "message": "Receiver is alive."})
    return jsonify({"status": "success", "message": "SIA receiver assumed alive."})

@app.route('/check_all_statuses')
@login_required
async def check_all_statuses():
    yolink_status = await check_mqtt_connection_active()
    monitor_status = await check_monitor_connection_active()

    config = load_config()
    modbus_active = False
    modbus_message = "Modbus relay is disabled"
    if config.get("modbus", {}).get("enabled", False):
        try:
            modbus_relay.config["modbus"] = config["modbus"]
            modbus_active = await modbus_relay.ensure_connection()
            modbus_message = "Modbus Relay Connected" if modbus_active else "Modbus Relay Disconnected"
        except Exception as e:
            logger.error(f"Error checking Modbus status: {e}")
            modbus_message = f"Error checking Modbus relay: {str(e)}"

    receiver_type = config.get("receiver_type", "CHEKT")
    receiver_message = "Receiver Connected"
    if receiver_type == "CHEKT":
        receiver_message = "CHEKT Receiver Connected"
    elif receiver_type == "SIA":
        receiver_message = "SIA Receiver Assumed Connected"

    return jsonify({
        "yolink": yolink_status,
        "monitor": monitor_status,
        "receiver": {"status": "success", "message": receiver_message},
        "modbus": {"status": "success" if modbus_active else "error", "message": modbus_message}
    })

@app.route('/last_refresh')
@login_required
async def last_refresh():
    try:
        last_refresh_time = await redis_client.get("last_refresh_time")
        if last_refresh_time:
            last_time = datetime.fromtimestamp(float(last_refresh_time))
            formatted_time = last_time.strftime("%Y-%m-%d %H:%M:%S")
            time_ago = (datetime.now() - last_time).total_seconds() / 60.0
            return jsonify({
                "status": "success",
                "last_refresh": formatted_time,
                "minutes_ago": round(time_ago, 1)
            })
        return jsonify({
            "status": "success",
            "last_refresh": "Never",
            "minutes_ago": None
        })
    except Exception as e:
        logger.error(f"Error getting last refresh time: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/restart_services', methods=['POST'])
@login_required
async def restart_services():
    try:
        # For simplicity, just trigger a refresh of background services by restarting the scheduler
        await scheduler.shutdown(wait=False)
        await scheduler.start()
        return jsonify({"status": "success", "message": "Services restarted"})
    except Exception as e:
        logger.error(f"Error restarting services: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/save_relay_mapping", methods=["POST"])
@login_required
async def save_relay_mapping_route():
    data = await request.get_json()
    device_id = data.get("yolink_device_id")
    relay_channel = data.get("relay_channel", "N/A")
    use_relay = data.get("use_relay", False)

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(f"Saving relay mapping for device {device_id}: Channel {relay_channel}, Use Relay: {use_relay}")
    save_mapping(device_id, relay_channel=relay_channel, use_relay=use_relay)
    return jsonify({"status": "success"})

@app.route('/check_modbus_status')
@login_required
async def check_modbus_status():
    config = load_config()
    if not config.get("modbus", {}).get("enabled", False):
        return jsonify({"status": "warning", "message": "Modbus relay is disabled in configuration."})

    try:
        modbus_relay.config["modbus"] = config["modbus"]
        is_connected = await modbus_relay.ensure_connection()
        return jsonify({
            "status": "success" if is_connected else "error",
            "message": "Modbus relay connection is active." if is_connected else "Modbus relay connection is inactive."
        })
    except Exception as e:
        logger.error(f"Error checking Modbus status: {e}")
        return jsonify({"status": "error", "message": f"Error checking Modbus status: {str(e)}"}), 500

@app.route('/test_relay_channel', methods=['POST'])
@login_required
async def test_relay_channel():
    data = await request.get_json()
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
        modbus_relay.config["modbus"] = config["modbus"]
        if not await modbus_relay.ensure_connection():
            return jsonify({"status": "error", "message": "Cannot connect to Modbus relay"}), 500

        on_success = await modbus_relay.trigger_relay(channel, True, 1.0)
        if not on_success:
            return jsonify({"status": "error", "message": f"Failed to turn on relay channel {channel}"}), 500

        return jsonify({"status": "success", "message": f"Relay channel {channel} pulsed successfully"})
    except Exception as e:
        logger.error(f"Error testing relay channel {channel}: {e}")
        return jsonify({"status": "error", "message": f"Error testing relay: {str(e)}"}), 500

@app.route('/test_modbus', methods=['GET'])
@login_required
async def test_modbus():
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
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get("http://modbus-proxy:5000/healthcheck", timeout=2) as response:
                if response.status == 200:
                    data = await response.json()
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

    # Test 2: Test proxy configuration
    try:
        modbus_relay.config["modbus"] = modbus_config
        config_result = await modbus_relay.configure_proxy(modbus_ip, modbus_port)
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

    # Test 3: Full Modbus connectivity
    try:
        connection_result = await modbus_relay.ensure_connection()
        results["tests"].append({
            "name": "Modbus Connection",
            "success": connection_result,
            "message": f"Modbus connection {'successful' if connection_result else 'failed'}"
        })
    except Exception as e:
        results["tests"].append({
            "name": "Modbus Connection",
            "success": False,
            "message": f"Modbus connection test error: {str(e)}"
        })

    # Test 4: Try a single relay operation
    if any(test["name"] == "Modbus Connection" and test["success"] for test in results["tests"]):
        try:
            relay_result = await modbus_relay.trigger_relay(1, True, 0.5)
            results["tests"].append({
                "name": "Relay Operation",
                "success": relay_result,
                "message": f"Relay trigger {'successful' if relay_result else 'failed'}"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Relay Operation",
                "success": False,
                "message": f"Relay test error: {str(e)}"
            })

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

# ----------------------- Main Entry -----------------------

async def init_default_user() -> None:
    """Create a default admin user if no users exist."""
    keys = await redis_client.keys("user:*")
    if not keys:
        default_username = "admin"
        default_password = "admin123"
        hashed_password = await bcrypt.hashpw(default_password.encode('utf-8'))
        user_data = {"password": hashed_password.decode('utf-8'), "force_password_change": True}
        save_user_data(default_username, user_data)
        logger.info("Created default admin user")

# The main() function is not used when running under Gunicorn.
# When running standalone, you can start the Quart server with:
#   quart run --host=0.0.0.0 --port=5000
if __name__ == "__main__":
    asyncio.run(app.run(host='0.0.0.0', port=int(os.getenv("API_PORT", 5000))))
