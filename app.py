"""
Yolink to CHEKT Integration - Version 1.4 (Enhanced with HTTPS)
======================================================

Main application file for integrating Yolink smart sensors with the CHEKT alarm system
and Modbus relays via MQTT, with a robust web interface for management, served over HTTPS.
"""

import os
import logging
import base64
import io
import asyncio
import ssl
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, List
from quart import Quart, request, render_template, flash, redirect, url_for, session, jsonify
from quart_auth import (
    QuartAuth, AuthUser, login_required,
    logout_user, login_user, Unauthorized, current_user
)
from quart_bcrypt import Bcrypt
from redis_manager import get_redis, ensure_connection as ensure_redis_connection, close as close_redis, get_pool_stats
import pyotp
import qrcode
import psutil
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
import aiohttp

# Load environment variables
load_dotenv()

# Import local modules
from config import load_config, save_config, get_user_data, save_user_data, SUPPORTED_TIMEZONES
from device_manager import refresh_yolink_devices, get_all_devices
from mappings import get_mappings, save_mapping, save_mappings
from yolink_mqtt import run_mqtt_client, shutdown_yolink_mqtt, is_connected as yolink_connected
from monitor_mqtt import run_monitor_mqtt, shutdown_monitor_mqtt, is_connected as monitor_connected
from modbus_relay import initialize as modbus_initialize, shutdown_modbus, ensure_connection as modbus_ensure_connection, trigger_relay, configure_proxy
from redis_manager import get_redis, ensure_connection as ensure_redis_connection, close as close_redis
from websocket_handler import init_websocket  # Import WebSocket handler

# Initialize Quart app
app = Quart(__name__, template_folder='templates')  # Explicitly set template folder
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "default-secret-key")
app.config["SESSION_COOKIE_SECURE"] = os.getenv("ENV", "development") != "development"  # True in prod, False in dev
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JS access to cookies
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
if app.config["SECRET_KEY"] == "default-secret-key":
    logging.warning("Using default SECRET_KEY; set FLASK_SECRET_KEY in .env for security")

# Logging Setup
os.makedirs("/app/logs", exist_ok=True)
handler = RotatingFileHandler("/app/logs/app.log", maxBytes=10*1024*1024, backupCount=5)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Extensions
class User(AuthUser):
    def __init__(self, auth_id: Optional[str]) -> None:
        super().__init__(auth_id)

    @property
    def is_authenticated(self) -> bool:
        return self.auth_id is not None

bcrypt = Bcrypt(app)
auth = QuartAuth(app)
scheduler = AsyncIOScheduler()
app.bg_tasks: List[asyncio.Task] = []

# Initialize WebSocket functionality
init_websocket(app)

# ----------------------- Middleware -----------------------

@app.before_request
async def enforce_https():
    """Redirect HTTP requests to HTTPS in production unless DISABLE_HTTPS is true, respecting proxy headers."""
    # Load DISABLE_HTTPS from environment
    disable_https = os.getenv("DISABLE_HTTPS", "false").lower() == "true"

    # Skip redirection if HTTPS is disabled
    if disable_https:
        return

    # Check if the request is from an internal Docker network (172.16.0.0/12 range)
    remote_addr = request.remote_addr
    try:
        # Convert IP to integer for range checking
        ip_parts = [int(part) for part in remote_addr.split('.')]
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        docker_range_start = (172 << 24) + (16 << 16)  # 172.16.0.0
        docker_range_end = (172 << 24) + (31 << 16) + (255 << 8) + 255  # 172.31.255.255
        if docker_range_start <= ip_int <= docker_range_end:
            return
    except (ValueError, IndexError):
        logger.warning(f"Could not parse remote_addr: {remote_addr}, proceeding with HTTPS check")

    # Redirect to HTTPS only in production and if not already HTTPS
    if app.config["ENV"] != "development" and request.scheme != "https" and request.headers.get('X-Forwarded-Proto') != 'https':
        # Prefer proxy headers for host
        host = (request.headers.get('X-Forwarded-Host') or
                request.headers.get('X-Forwarded-Server') or
                request.headers.get('Host'))

        # Fallback to local IP if no valid host is found or if it’s an internal name
        if not host or 'yolink_chekt' in host:
            import socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(('8.8.8.8', 80))
                    host = s.getsockname()[0]
            except Exception:
                host = '127.0.0.1'

        # Construct redirect URL
        path = request.path
        query_string = request.query_string.decode('utf-8')
        if query_string:
            path = f"{path}?{query_string}"
        redirect_url = f"https://{host}{path}"
        logger.debug(f"Redirecting HTTP request to HTTPS: {redirect_url}")
        return redirect(redirect_url, code=301)

# ----------------------- Authentication Helpers -----------------------

async def init_default_user() -> None:
    """Create a default admin user if no users exist."""
    try:
        redis_client = await get_redis()
        keys = await redis_client.keys("user:*")
        if not keys:
            default_username = "admin"
            default_password = "admin123"
            hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
            user_data = {"password": hashed_password, "force_password_change": True}  # Changed to True for consistency
            await save_user_data(default_username, user_data)
            logger.info("Created default admin user")
    except Exception as e:
        logger.error(f"Error creating default user: {e}")

# ----------------------- Utility Functions -----------------------

async def check_mqtt_connection_active() -> Dict[str, Any]:
    """Check if YoLink MQTT connection is functional."""
    try:
        if yolink_connected():
            return {"status": "success", "message": "YoLink MQTT connection is active."}
        return {"status": "error", "message": "YoLink MQTT connection is inactive."}
    except Exception as e:
        logger.error(f"Error checking YoLink MQTT connection: {e}")
        return {"status": "error", "message": f"Error checking YoLink MQTT: {str(e)}"}

async def check_monitor_connection_active() -> Dict[str, Any]:
    """Check if Monitor MQTT connection is functional."""
    try:
        if monitor_connected():
            return {"status": "success", "message": "Monitor MQTT connection is active."}
        return {"status": "error", "message": "Monitor MQTT connection is inactive."}
    except Exception as e:
        logger.error(f"Error checking Monitor MQTT connection: {e}")
        return {"status": "error", "message": f"Error checking Monitor MQTT: {str(e)}"}

async def is_system_configured() -> bool:
    """Check if the system has necessary credentials configured."""
    config = await load_config()
    yolink_configured = bool(config.get("yolink", {}).get("uaid") and config.get("yolink", {}).get("secret_key"))
    monitor_configured = bool(config.get("mqtt_monitor", {}).get("url"))
    receiver_configured = any([
        config.get("chekt", {}).get("enabled", True),
        config.get("sia", {}).get("enabled", False),
        config.get("modbus", {}).get("enabled", False)
    ])
    return yolink_configured and monitor_configured and receiver_configured

# ----------------------- Background Startup & Shutdown -----------------------

@app.before_serving
async def startup() -> None:
    """Initialize background services and resources."""
    logger.info("Starting application services")

    await asyncio.sleep(1)
    if not await ensure_redis_connection(max_retries=5, backoff_base=1.5):
        logger.error("Failed to connect to Redis after retries")
        raise SystemExit(1)

    stats = await get_pool_stats()
    logger.info(f"Redis pool stats before tasks: {stats}")

    await init_default_user()

    stats = await get_pool_stats()
    logger.debug(f"Redis pool stats before get_all_devices: {stats}")
    try:
        initial_devices = await get_all_devices()
        logger.info(f"Initial device fetch retrieved {len(initial_devices)} devices")
    except Exception as e:
        logger.error(f"Failed initial device fetch: {e}", exc_info=True)

    if await is_system_configured():
        logger.info("System configured, launching background tasks")

        app.bg_tasks.append(asyncio.create_task(run_mqtt_client()))
        app.config['shutdown_yolink'] = shutdown_yolink_mqtt
        await asyncio.sleep(1)
        stats = await get_pool_stats()
        logger.debug(f"Redis pool stats after YoLink MQTT: {stats}")

        app.bg_tasks.append(asyncio.create_task(run_monitor_mqtt()))
        app.config['shutdown_monitor'] = shutdown_monitor_mqtt
        await asyncio.sleep(1)
        stats = await get_pool_stats()
        logger.debug(f"Redis pool stats after Monitor MQTT: {stats}")

        app.bg_tasks.append(asyncio.create_task(modbus_initialize()))
        app.config['shutdown_modbus'] = shutdown_modbus
        await asyncio.sleep(1)
        stats = await get_pool_stats()
        logger.info(f"Redis pool stats after all tasks started: {stats}")
    else:
        logger.warning("System not fully configured; skipping background tasks")
        app.config['shutdown_yolink'] = None
        app.config['shutdown_monitor'] = None
        app.config['shutdown_modbus'] = None

    scheduler.start()
    logger.info("Scheduler started")

@app.after_serving
async def shutdown() -> None:
    """Gracefully shut down services and resources."""
    logger.info("Shutting down application services")

    shutdown_functions = [
        (app.config.get('shutdown_modbus'), "Modbus relay"),
        (app.config.get('shutdown_monitor'), "Monitor MQTT"),
        (app.config.get('shutdown_yolink'), "YoLink MQTT")
    ]

    for fn, name in shutdown_functions:
        if fn:
            try:
                if asyncio.iscoroutinefunction(fn):
                    await fn()
                else:
                    await asyncio.to_thread(fn)
                logger.info(f"Shutdown {name} completed")
            except Exception as e:
                logger.error(f"Failed to shutdown {name}: {e}")

    # Cancel background tasks
    for task in app.bg_tasks:
        if not task.done():
            task.cancel()
    if app.bg_tasks:
        await asyncio.wait(app.bg_tasks, timeout=10)

    # Shutdown scheduler
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")

    # Close Redis
    await close_redis()
    logger.info("Shutdown complete")

# ----------------------- Authentication Routes -----------------------

@app.route("/login", methods=["GET", "POST"])
async def login():
    """
    Handle user login with a streamlined first-time workflow.
    """
    logger.debug(f"Request method: {request.method}, Form data: {await request.form}")
    if request.method == "POST":
        form = await request.form
        username = form.get("username", "").strip()
        password = form.get("password", "")
        totp_code = form.get("totp_code", "").strip()
        logger.debug(f"Username: {username}, Password: {'***' if password else ''}, TOTP: {totp_code}, Session: {session}")

        # Handle TOTP submission
        if totp_code and "pending_user" in session:
            username = session["pending_user"]
            user_data = await get_user_data(username)
            logger.debug(f"TOTP step - User data: {user_data}")
            if not user_data:
                await flash("Session expired or invalid user", "error")
                session.pop("pending_user", None)
                return await render_template("login.html", totp_required=False)

            totp = pyotp.TOTP(user_data["totp_secret"])
            if not totp.verify(totp_code):
                logger.info(f"Failed TOTP verification for {username}")
                await flash("Invalid TOTP code", "error")
                return await render_template("login.html", totp_required=True, username=username)

            login_user(User(username))
            session.pop("pending_user", None)
            logger.info(f"User {username} logged in successfully with TOTP")
            return redirect(url_for("index"))

        # Initial login with username/password
        if not username or not password:
            await flash("Username and password are required", "error")
            logger.debug("Login attempt failed: Missing username or password")
            return await render_template("login.html", totp_required=False)

        user_data = await get_user_data(username)
        logger.debug(f"Initial login - User data for {username}: {user_data}")
        if not user_data:
            logger.info(f"Login attempt with non-existent username: {username}")
            await flash("Invalid credentials", "error")
            return await render_template("login.html", totp_required=False)

        try:
            if not bcrypt.check_password_hash(user_data["password"], password):
                logger.info(f"Failed login attempt for {username}: incorrect password")
                await flash("Invalid credentials", "error")
                return await render_template("login.html", totp_required=False)
        except Exception as e:
            logger.error(f"Error verifying password for {username}: {e}")
            await flash("Authentication error", "error")
            return await render_template("login.html", totp_required=False)

        # Authentication successful, set session and determine next step
        session["pending_user"] = username
        logger.debug(f"Session set with pending_user: {username}")

        if user_data.get("force_password_change", False):
            login_user(User(username))
            logger.info(f"First-time login for {username}, redirecting to change password")
            await flash("Please change your default password", "warning")
            return redirect(url_for("change_password"))

        if "totp_secret" not in user_data:
            login_user(User(username))
            logger.info(f"User {username} logged in, no TOTP set, redirecting to setup")
            return redirect(url_for("setup_totp"))

        logger.debug(f"TOTP required for {username}, prompting for code")
        return await render_template("login.html", totp_required=True, username=username)

    # GET request: Check for pending TOTP step
    pending_user = session.get("pending_user")
    if pending_user:
        user_data = await get_user_data(pending_user)
        logger.debug(f"GET request - Pending user data: {user_data}")
        if user_data and "totp_secret" in user_data:
            logger.debug(f"Pending user {pending_user} found in session, showing TOTP prompt")
            return await render_template("login.html", totp_required=True, username=pending_user)
    return await render_template("login.html", totp_required=False)


@app.route("/logout")
@login_required
async def logout():
    """Log out the current user."""
    username = auth.current_user.auth_id
    logout_user()
    logger.info(f"User {username} logged out")
    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
async def change_password():
    """Handle password change and redirect to TOTP setup if needed."""
    user_data = await get_user_data(current_user.auth_id)  # Changed from auth.current_user.auth_id
    logger.debug(f"Change password - User data: {user_data}")
    if request.method == "POST":
        form = await request.form
        current_password = form.get("current_password", "")
        new_password = form.get("new_password", "")
        confirm_password = form.get("confirm_password", "")

        if not bcrypt.check_password_hash(user_data["password"], current_password):
            await flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            await flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            await flash("Password must be at least 8 characters", "error")
        else:
            user_data["password"] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_data["force_password_change"] = False
            await save_user_data(current_user.auth_id, user_data)  # Changed from auth.current_user.auth_id
            logger.info(f"User {current_user.auth_id} changed password successfully")  # Changed from auth.current_user.auth_id
            if "totp_secret" not in user_data:
                await flash("Password changed, now set up two-factor authentication", "success")
                return redirect(url_for("setup_totp"))
            await flash("Password changed successfully", "success")
            return redirect(url_for("index"))

    return await render_template("change_password.html")


@app.route("/setup_totp", methods=["GET", "POST"])
@login_required
async def setup_totp():
    """Set up TOTP and redirect to dashboard."""
    user_data = await get_user_data(current_user.auth_id)
    if "totp_secret" in user_data:
        await flash("TOTP already set up", "info")
        return redirect(url_for("index"))

    if request.method == "POST":
        form = await request.form
        totp_code = form.get("totp_code")
        totp_secret = session.get("totp_secret")
        if not totp_secret:
            await flash("Session expired, please try again", "error")
            return redirect(url_for("setup_totp"))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            user_data["totp_secret"] = totp_secret
            await save_user_data(current_user.auth_id, user_data)
            session.pop("totp_secret", None)
            logger.info(f"User {current_user.auth_id} completed TOTP setup")
            await flash("TOTP setup complete, you’re all set!", "success")
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
    return await render_template("setup_totp.html", qr_img=qr_img, totp_secret=totp_secret)  # Added totp_secret

# ----------------------- Main Routes -----------------------

@app.route("/")
@login_required
async def index():
    """Render the main dashboard page."""
    user_data = await get_user_data(current_user.auth_id)  # Changed from auth.current_user.auth_id
    if user_data.get("force_password_change", False):
        await flash("Please change your default password.", "warning")
        return redirect(url_for("change_password"))

    devices = await get_all_devices()
    mappings = await get_mappings()
    mappings_list = mappings.get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings_list}
    for device in devices:
        mapping = device_mappings.get(device["deviceId"], {})
        device["chekt_zone"] = mapping.get("chekt_zone", "N/A")
        device["door_prop_alarm"] = mapping.get("door_prop_alarm", False)

    return await render_template("index.html", devices=devices)

@app.route("/config", methods=["GET", "POST"])
@login_required
async def config():
    """Handle configuration viewing and updates."""
    config_data = await load_config()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == "POST":
        try:
            form = await request.form
            if not form.get("yolink_uaid") or not form.get("yolink_secret_key"):
                error_msg = "YoLink UAID and Secret Key are required"
                if is_ajax:
                    return jsonify({"status": "error", "message": error_msg}), 400
                await flash(error_msg, "error")
                return redirect(url_for("config"))

            # Helper function to safely parse integers with a default
            def safe_int(value, default, field_name):
                try:
                    return int(value) if value else default
                except ValueError:
                    raise ValueError(f"Invalid {field_name}: '{value}' must be an integer")

            # Parse form data with safe defaults
            chekt_enabled = form.get("chekt_enabled") == "on"
            sia_enabled = form.get("sia_enabled") == "on"
            modbus_enabled = form.get("modbus_enabled") == "on"
            modbus_follower_mode = form.get("modbus_follower_mode") == "on"

            new_config = {
                "yolink": {
                    "uaid": form.get("yolink_uaid", ""),
                    "secret_key": form.get("yolink_secret_key", ""),
                    "token": config_data["yolink"].get("token", ""),
                    "issued_at": config_data["yolink"].get("issued_at", 0),
                    "expires_in": config_data["yolink"].get("expires_in", 0)
                },
                "mqtt": {
                    "url": form.get("yolink_url", "mqtt://api.yosmart.com"),
                    "port": safe_int(form.get("yolink_port"), 8003, "YoLink MQTT Port"),
                    "topic": form.get("yolink_topic", "yl-home/${Home ID}/+/report")
                },
                "mqtt_monitor": {
                    "url": form.get("monitor_mqtt_url", "mqtt://monitor.industrialcamera.com"),
                    "port": safe_int(form.get("monitor_mqtt_port"), 1883, "Monitor MQTT Port"),
                    "username": form.get("monitor_mqtt_username", ""),
                    "password": form.get("monitor_mqtt_password", ""),
                    "client_id": "monitor_client_id"
                },
                "receiver_type": form.get("receiver_type", "CHEKT"),
                "chekt": {
                    "api_token": form.get("chekt_api_token", ""),
                    "ip": form.get("chekt_ip", ""),
                    "port": safe_int(form.get("chekt_port"), 30003, "CHEKT Receiver Port"),
                    "enabled": chekt_enabled
                },
                "sia": {
                    "ip": form.get("sia_ip", ""),
                    "port": safe_int(form.get("sia_port"), 0, "SIA Port") or "",  # Allow empty port if SIA disabled
                    "account_id": form.get("sia_account_id", ""),
                    "transmitter_id": form.get("sia_transmitter_id", ""),
                    "encryption_key": form.get("sia_encryption_key", ""),
                    "enabled": sia_enabled
                },
                "modbus": {
                    "ip": form.get("modbus_ip", ""),
                    "port": safe_int(form.get("modbus_port"), 502, "Modbus Relay Port"),
                    "unit_id": safe_int(form.get("modbus_unit_id"), 1, "Modbus Unit ID"),
                    "max_channels": safe_int(form.get("modbus_max_channels"), 16, "Modbus Max Channels"),
                    "pulse_seconds": float(form.get("modbus_pulse_seconds", 1.0)),
                    "enabled": modbus_enabled,
                    "follower_mode": modbus_follower_mode
                },
                "monitor": {"api_key": form.get("monitor_api_key", "")},
                "timezone": "UTC",
                "door_open_timeout": safe_int(form.get("door_open_timeout"), 30, "Door Open Timeout"),
                "home_id": config_data.get("home_id", ""),
                "supported_timezones": SUPPORTED_TIMEZONES
            }
            await save_config(new_config)
            success_msg = "Configuration saved"
            if is_ajax:
                return jsonify({"status": "success", "message": success_msg})
            await flash(success_msg, "success")
            return redirect(url_for("config"))
        except ValueError as e:
            logger.error(f"Invalid input in configuration: {str(e)}")
            if is_ajax:
                return jsonify({"status": "error", "message": str(e)}), 400
            await flash(f"Invalid input: {str(e)}", "error")
            return redirect(url_for("config"))
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            if is_ajax:
                return jsonify({"status": "error", "message": str(e)}), 500
            await flash(f"Error saving configuration: {str(e)}", "error")
            return redirect(url_for("config"))

    return await render_template("config.html", config=config_data)

@app.route('/get_config')
@login_required
async def get_config():
    """Return the current configuration as JSON."""
    config = await load_config()
    return jsonify(config)

# ----------------------- User Management -----------------------

@app.route("/create_user", methods=["POST"])
@login_required
async def create_user():
    """Create a new user with a password."""
    form = await request.form
    username = form.get("username", "")
    password = form.get("password", "")

    if not username or not password:
        await flash("Username and password required", "error")
        return redirect(url_for("config"))

    if len(password) < 8:
        await flash("Password must be at least 8 characters", "error")
        return redirect(url_for("config"))

    existing_user = await get_user_data(username)
    if existing_user:
        await flash("Username already exists", "error")
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Removed await
        user_data = {"password": hashed_password, "force_password_change": True}
        await save_user_data(username, user_data)
        await flash("User created successfully", "success")
    return redirect(url_for("config"))

# ----------------------- Device Management -----------------------

@app.route("/refresh_devices")
@login_required
async def refresh_devices():
    """Refresh the list of YoLink devices."""
    try:
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
        await refresh_yolink_devices()
        if is_ajax:
            return jsonify({"status": "success", "message": "Devices refreshed successfully"})
        await flash("Devices refreshed successfully", "success")
        return redirect(url_for("index"))
    except Exception as e:
        logger.error(f"Device refresh failed: {e}")
        if is_ajax:
            return jsonify({"status": "error", "message": f"Failed to refresh devices: {str(e)}"}), 500
        await flash("Failed to refresh devices", "error")
        return redirect(url_for("index"))

@app.route("/system_uptime")
@login_required
async def system_uptime():
    """Return the system uptime in seconds."""
    boot_time = psutil.boot_time()
    current_time = datetime.now().timestamp()
    uptime_seconds = current_time - boot_time
    return jsonify({"uptime_seconds": uptime_seconds})

@app.route("/save_mapping", methods=["POST"])
@login_required
async def save_mapping_route():
    """Save a mapping for a YoLink device."""
    data = await request.get_json()
    device_id = data.get("yolink_device_id")
    chekt_zone = data.get("chekt_zone", "N/A")

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(f"Saving CHEKT zone for device {device_id}: {chekt_zone}")
    await save_mapping(device_id, chekt_zone)
    return jsonify({"status": "success"})

@app.route("/set_door_prop_alarm", methods=["POST"])
@login_required
async def set_door_prop_alarm():
    """Set the door prop alarm setting for a device."""
    data = await request.get_json()
    device_id = data.get("device_id")
    enabled = data.get("enabled", False)

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(f"Setting door prop alarm for device {device_id} to {enabled}")
    mappings = await get_mappings()
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
    await save_mappings(mappings)
    return jsonify({"status": "success"})

@app.route("/get_sensor_data") #Internal API Endpoint. Consider adding API key security for the future.
async def get_sensor_data():
    """Return sensor data for all devices."""
    devices = await get_all_devices()
    mappings = await get_mappings()
    mappings_list = mappings.get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings_list}

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
    """Return the last 50 lines of application logs."""
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
    """Check the status of the YoLink MQTT connection."""
    return jsonify(await check_mqtt_connection_active())

@app.route("/check_monitor_mqtt_status")
@login_required
async def check_monitor_mqtt_status():
    """Check the status of the Monitor MQTT connection."""
    return jsonify(await check_monitor_connection_active())

@app.route("/check_receiver_status")
@login_required
async def check_receiver_status():
    """Check the status of the configured receiver."""
    config = await load_config()
    receiver_type = config.get("receiver_type", "CHEKT")
    return jsonify({"status": "success", "message": f"{receiver_type} receiver assumed alive."})

@app.route('/check_all_statuses')
@login_required
async def check_all_statuses():
    """Check the status of all services."""
    yolink_status = await check_mqtt_connection_active()
    monitor_status = await check_monitor_connection_active()
    config = await load_config()
    modbus_active = config.get("modbus", {}).get("enabled", False) and await modbus_ensure_connection()
    modbus_message = "Modbus Relay Connected" if modbus_active else "Modbus Relay Disconnected or Disabled"
    receiver_type = config.get("receiver_type", "CHEKT")
    return jsonify({
        "yolink": yolink_status,
        "monitor": monitor_status,
        "receiver": {"status": "success", "message": f"{receiver_type} Receiver Connected"},
        "modbus": {"status": "success" if modbus_active else "error", "message": modbus_message}
    })

@app.route('/last_refresh')
@login_required
async def last_refresh():
    """Return the time of the last device refresh."""
    try:
        redis_client = await get_redis()
        last_refresh_time = await redis_client.get("last_refresh_time")
        if last_refresh_time:
            last_time = datetime.fromtimestamp(float(last_refresh_time))
            formatted_time = last_time.strftime("%Y-%m-%d %H:%M:%S")
            time_ago = (datetime.now() - last_time).total_seconds() / 60.0
            return jsonify({"status": "success", "last_refresh": formatted_time, "minutes_ago": round(time_ago, 1)})
        return jsonify({"status": "success", "last_refresh": "Never", "minutes_ago": None})
    except Exception as e:
        logger.error(f"Error getting last refresh time: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/restart_services', methods=['POST'])
@login_required
async def restart_services():
    """Restart MQTT services with proper task management."""
    try:
        # Identify which tasks are MQTT-related and which are not
        mqtt_tasks = []
        non_mqtt_tasks = []

        for task in app.bg_tasks:
            if not task.done():
                task_str = str(task.get_coro() if hasattr(task, 'get_coro') else task)
                if 'run_mqtt_client' in task_str or 'run_monitor_mqtt' in task_str:
                    mqtt_tasks.append(task)
                else:
                    non_mqtt_tasks.append(task)

        logger.info(f"Restarting services: Found {len(mqtt_tasks)} MQTT tasks and {len(non_mqtt_tasks)} other tasks")

        # Shut down MQTT clients
        if app.config.get('shutdown_yolink'):
            app.config['shutdown_yolink']()
            logger.info("Shutdown signal sent to YoLink MQTT client")
        if app.config.get('shutdown_monitor'):
            app.config['shutdown_monitor']()
            logger.info("Shutdown signal sent to Monitor MQTT client")

        # Wait for MQTT tasks to complete with timeout
        if mqtt_tasks:
            logger.info("Waiting for MQTT tasks to complete...")
            try:
                done, pending = await asyncio.wait(mqtt_tasks, timeout=5)
                if pending:
                    logger.warning(f"{len(pending)} MQTT tasks did not complete in time, cancelling")
                    for task in pending:
                        task.cancel()
                    await asyncio.wait(pending, timeout=2)
            except Exception as e:
                logger.error(f"Error waiting for MQTT tasks: {e}")

        # Check if system is still properly configured
        if not await is_system_configured():
            logger.warning("System not fully configured after config change, can't restart MQTT services")
            return jsonify({
                "status": "warning",
                "message": "Configuration saved but MQTT services not started (missing or invalid credentials)"
            })

        # Start new MQTT tasks and preserve other tasks
        logger.info("Starting new MQTT tasks")

        # Create new task list with non-MQTT tasks
        app.bg_tasks = non_mqtt_tasks.copy()

        # Add new MQTT tasks
        yolink_task = asyncio.create_task(run_mqtt_client())
        app.bg_tasks.append(yolink_task)

        monitor_task = asyncio.create_task(run_monitor_mqtt())
        app.bg_tasks.append(monitor_task)

        # Log success
        logger.info(f"MQTT services restarted, total background tasks: {len(app.bg_tasks)}")

        # Wait a moment for tasks to start
        await asyncio.sleep(1)

        return jsonify({"status": "success", "message": "MQTT services restarted successfully"})
    except Exception as e:
        logger.error(f"Error restarting MQTT services: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to restart services: {str(e)}"}), 500

@app.route("/save_relay_mapping", methods=["POST"])
@login_required
async def save_relay_mapping_route():
    """Save relay mapping for a device."""
    data = await request.get_json()
    device_id = data.get("yolink_device_id")
    relay_channel = data.get("relay_channel", "N/A")
    use_relay = data.get("use_relay", False)

    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400

    logger.debug(f"Saving relay mapping for device {device_id}: Channel {relay_channel}, Use Relay: {use_relay}")
    await save_mapping(device_id, relay_channel=relay_channel, use_relay=use_relay)
    return jsonify({"status": "success"})

@app.route('/check_modbus_status')
@login_required
async def check_modbus_status():
    """Check the status of the Modbus relay connection."""
    config = await load_config()
    if not config.get("modbus", {}).get("enabled", False):
        return jsonify({"status": "warning", "message": "Modbus relay is disabled in configuration."})
    try:
        is_connected = await modbus_ensure_connection()
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
    """Test a specific relay channel."""
    data = await request.get_json()
    channel = data.get('channel')
    if not channel:
        return jsonify({"status": "error", "message": "Missing channel number"}), 400

    try:
        channel = int(channel)
        config = await load_config()
        if not config.get("modbus", {}).get("enabled", False):
            return jsonify({"status": "error", "message": "Modbus relay is disabled"}), 400
        if not await modbus_ensure_connection():
            return jsonify({"status": "error", "message": "Cannot connect to Modbus relay"}), 500

        # Use is_test=True to ensure it always pulses off, regardless of follower mode
        success = await trigger_relay(channel, True, 1.0, is_test=True)
        return jsonify({"status": "success" if success else "error",
                        "message": f"Relay channel {channel} pulsed {'successfully' if success else 'failed'}"})
    except Exception as e:
        logger.error(f"Error testing relay channel {channel}: {e}")
        return jsonify({"status": "error", "message": f"Error testing relay: {str(e)}"}), 500

@app.route('/test_modbus', methods=['GET'])
@login_required
async def test_modbus():
    """Perform a comprehensive test of the Modbus connection."""
    config = await load_config()
    modbus_config = config.get('modbus', {})
    if not modbus_config.get('enabled', False):
        return jsonify({"status": "warning", "message": "Modbus is not enabled"})

    modbus_ip = modbus_config.get('ip')
    modbus_port = modbus_config.get('port', 502)
    if not modbus_ip:
        return jsonify({"status": "error", "message": "Modbus IP not configured"})

    results = {"status": "checking", "tests": []}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get("http://modbus-proxy:5000/healthcheck", timeout=aiohttp.ClientTimeout(total=2)) as response:
                proxy_healthy = response.status == 200 and (await response.json()).get("status") == "healthy"
                results["tests"].append({
                    "name": "Modbus Proxy Health",
                    "success": proxy_healthy,
                    "message": f"Proxy service is {'healthy' if proxy_healthy else 'unhealthy'}"
                })
        except Exception as e:
            results["tests"].append({"name": "Modbus Proxy Health", "success": False, "message": f"Failed to reach proxy: {str(e)}"})

    try:
        config_result = await configure_proxy(modbus_ip, modbus_port)
        results["tests"].append({"name": "Proxy Configuration", "success": config_result, "message": f"Proxy configuration {'successful' if config_result else 'failed'}"})
    except Exception as e:
        results["tests"].append({"name": "Proxy Configuration", "success": False, "message": f"Error configuring proxy: {str(e)}"})

    try:
        connection_result = await modbus_ensure_connection()
        results["tests"].append({"name": "Modbus Connection", "success": connection_result, "message": f"Modbus connection {'successful' if connection_result else 'failed'}"})
    except Exception as e:
        results["tests"].append({"name": "Modbus Connection", "success": False, "message": f"Modbus connection error: {str(e)}"})

    if all(test["success"] for test in results["tests"] if test["name"] == "Modbus Connection"):
        try:
            # Use is_test=True to ensure relay turns off after test
            relay_result = await trigger_relay(1, True, 0.5, is_test=True)
            results["tests"].append({"name": "Relay Operation", "success": relay_result, "message": f"Relay trigger {'successful' if relay_result else 'failed'}"})
        except Exception as e:
            results["tests"].append({"name": "Relay Operation", "success": False, "message": f"Relay test error: {str(e)}"})

    success_count = sum(1 for test in results["tests"] if test["success"])
    results["status"] = "success" if success_count == len(results["tests"]) else "warning" if success_count > 0 else "error"
    results["message"] = f"{success_count}/{len(results['tests'])} tests passed"
    return jsonify(results)

# ----------------------- Error Handling -----------------------

@app.errorhandler(Unauthorized)
async def handle_unauthorized(error):
    """Redirect unauthorized users to the login page."""
    return redirect(url_for("login"))

@app.errorhandler(404)
async def page_not_found(error):
    """Handle 404 errors."""
    return await render_template("error.html", error="Page not found"), 404

@app.errorhandler(500)
async def server_error(error):
    """Handle 500 errors."""
    logger.error(f"Server error: {error}")
    return await render_template("error.html", error="Internal server error"), 500


if __name__ == "__main__":
    # Check if HTTPS should be disabled (when using Nginx as SSL terminator)
    disable_https = os.getenv("DISABLE_HTTPS", "false").lower() == "true"
    port = int(os.getenv("API_PORT", 5000))
    debug_mode = os.getenv("QUART_DEBUG", "false").lower() == "true"

    if disable_https:
        logger.info(f"Running in HTTP mode (SSL termination handled by Nginx) on port {port}")
        asyncio.run(app.run(
            host='0.0.0.0',
            port=port,
            debug=debug_mode
        ))
    else:
        # Check for certificate files - use certs directory for flexibility
        cert_paths = [
            ("/app/cert.pem", "/app/key.pem"),  # Original path
            ("/app/certs/cert.pem", "/app/certs/key.pem"),  # New path in volume
        ]

        cert_file = None
        key_file = None

        for cert_path, key_path in cert_paths:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                cert_file = cert_path
                key_file = key_path
                break

        if not cert_file or not key_file:
            logger.error("SSL certificates not found. Checking in all possible locations...")
            for path in ["/app", "/app/certs"]:
                if os.path.exists(path):
                    logger.info(f"Directory {path} exists, contents: {os.listdir(path)}")
            raise SystemExit(1)

        # Configure SSL context for HTTPS
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            logger.info(f"SSL certificates loaded successfully for HTTPS from {cert_file}")
        except Exception as e:
            logger.error(f"Failed to load SSL certificates: {e}")
            raise SystemExit(1)

        # Run the app with HTTPS
        logger.info(f"Running with HTTPS on port {port}")
        asyncio.run(app.run(
            host='0.0.0.0',
            port=port,
            ssl=ssl_context,
            debug=debug_mode
        ))