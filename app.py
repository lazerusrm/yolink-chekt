from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import threading
import secrets
import logging
import pyotp
import qrcode
import io
import base64
import requests
import socket
import time
import os
import json

from config import load_config, save_config, config_data, yolink_mqtt_status, monitor_mqtt_status  # Updated import
from yolink_mqtt import run_mqtt_client, generate_yolink_token, is_token_expired, device_data
from device_manager import load_devices_to_redis, get_all_devices, get_device_data
from mappings import load_mappings_to_redis, get_mappings, get_mapping
from monitor_mqtt import initialize_monitor_mqtt_client
from db import redis_client

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load or generate a persistent SECRET_KEY
secret_key_file = "/app/secret.key"
if os.path.exists(secret_key_file):
    with open(secret_key_file, "rb") as f:
        app.secret_key = f.read()
else:
    app.secret_key = secrets.token_hex(32).encode('utf-8')
    with open(secret_key_file, "wb") as f:
        f.write(app.secret_key)
    logger.info("Generated and saved new SECRET_KEY to secret.key")

app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in config_data.get("users", {}) else None

def initialize_default_user():
    """Create a default admin user if no users exist."""
    if not config_data.get("users"):
        default_username = "admin"
        default_password = "admin12345"
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        config_data["users"] = {
            default_username: {
                "password": hashed_password,
                "force_password_change": True
            }
        }
        save_config()
        logger.info("Created default admin user: 'admin' with password 'admin12345'")

def refresh_yolink_token() -> bool:
    """Refresh YoLink token using UAID and Secret Key."""
    load_config()
    yolink_config = config_data.get("yolink", {})
    uaid = yolink_config.get("uaid", "")
    secret_key = yolink_config.get("secret_key", "")
    logger.info(f"Attempting token refresh with UAID: {uaid}, Secret Key: {secret_key}")
    if not uaid or not secret_key:
        logger.warning(f"UAID or Secret Key missing; token refresh skipped. UAID: {uaid}, Secret Key: {secret_key}")
        return False
    result = generate_yolink_token(uaid, secret_key)
    if result is None:
        logger.error(f"Failed to generate YoLink token with UAID: {uaid}, Secret Key: {secret_key}")
    return result is not None

@app.route("/")
@login_required
def index():
    if config_data["users"].get(current_user.id, {}).get("force_password_change", False):
        flash("Please change your default password before proceeding.", "warning")
        return redirect(url_for("change_password"))
    devices = get_all_devices()
    mappings = get_mappings().get("mappings", {})
    device_mappings = {m["yolink_device_id"]: m for m in mappings}
    for device in devices:
        device.update(device_data.get(device["deviceId"], {}))
    return render_template("index.html", devices=devices, mappings=device_mappings, config=config_data)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        totp_code = request.form.get("totp_code")
        users = config_data.get("users", {})
        if username in users and bcrypt.check_password_hash(users[username]["password"], password):
            if users[username].get("totp_secret") and not totp_code:
                return render_template("login.html", totp_required=True, username=username, password=password)
            if totp_code and users[username].get("totp_secret"):
                totp = pyotp.TOTP(users[username]["totp_secret"])
                if not totp.verify(totp_code):
                    flash("Invalid TOTP code", "error")
                    return render_template("login.html", totp_required=True, username=username, password=password)
            login_user(User(username))
            logger.info(f"User {username} logged in successfully")
            next_page = request.args.get("next", url_for("index"))
            if users[username].get("force_password_change", False):
                return redirect(url_for("change_password"))
            return redirect(next_page)
        flash("Invalid credentials", "error")
    no_users = not config_data.get("users")
    return render_template("login.html", totp_required=False, no_users=no_users)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/setup_totp", methods=["GET", "POST"])
@login_required
def setup_totp():
    if request.method == "POST":
        totp_code = request.form["totp_code"]
        totp_secret = session.get("totp_secret")
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            config_data["users"][current_user.id]["totp_secret"] = totp_secret
            save_config()
            session.pop("totp_secret", None)
            flash("TOTP setup complete", "success")
            return redirect(url_for("index"))
        flash("Invalid TOTP code", "error")
    totp_secret = pyotp.random_base32()
    session["totp_secret"] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(current_user.id, issuer_name="YoLink-CHEKT")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return render_template("setup_totp.html", qr_img=qr_img)

@app.route("/create_user", methods=["POST"])
@login_required
def create_user():
    username = request.form["username"]
    password = request.form["password"]
    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for("config"))
    if username in config_data.get("users", {}):
        flash("Username already exists", "error")
    else:
        config_data["users"][username] = {
            "password": bcrypt.generate_password_hash(password).decode('utf-8')
        }
        save_config()
        flash("User created successfully", "success")
    return redirect(url_for("config"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        user_data = config_data["users"].get(current_user.id, {})
        if not bcrypt.check_password_hash(user_data["password"], current_password):
            flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            flash("New password must be at least 8 characters", "error")
        else:
            user_data["password"] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_data["force_password_change"] = False
            save_config()
            logger.info(f"Config data after save in change_password: {config_data}")
            flash("Password changed successfully", "success")
            return redirect(url_for("index"))
        return render_template("change_password.html")
    return render_template("change_password.html")

@app.route("/config", methods=["GET", "POST"])
@login_required
def config():
    if config_data["users"].get(current_user.id, {}).get("force_password_change", False):
        flash("Please change your default password before proceeding.", "warning")
        return redirect(url_for("change_password"))
    if request.method == "POST":
        try:
            yolink_port = int(request.form["yolink_port"])
            monitor_port = int(request.form["monitor_mqtt_port"])
            sia_port = request.form.get("sia_port", "")
            sia_port = int(sia_port) if sia_port else ""
            chekt_port = int(request.form["chekt_port"])
            door_timeout = int(request.form["door_open_timeout"])
            if yolink_port < 1 or yolink_port > 65535 or monitor_port < 1 or monitor_port > 65535 or chekt_port < 1 or chekt_port > 65535:
                raise ValueError("Ports must be between 1 and 65535")
            if sia_port and (sia_port < 1 or sia_port > 65535):
                raise ValueError("SIA port must be between 1 and 65535")
            if door_timeout < 1:
                raise ValueError("Door open timeout must be positive")

            new_config = {
                "yolink": {
                    "uaid": request.form["yolink_uaid"],
                    "secret_key": request.form["yolink_secret_key"],
                    "token": config_data.get("yolink", {}).get("token", ""),
                    "token_expiry": config_data.get("yolink", {}).get("token_expiry", 0)
                },
                "mqtt": {
                    "url": request.form["yolink_url"],
                    "port": yolink_port,
                    "topic": request.form["yolink_topic"]
                },
                "mqtt_monitor": {
                    "url": request.form["monitor_mqtt_url"],
                    "port": monitor_port,
                    "username": request.form["monitor_mqtt_username"],
                    "password": request.form["monitor_mqtt_password"],
                    "client_id": "monitor_client_id"
                },
                "receiver_type": request.form["receiver_type"],
                "chekt": {
                    "api_token": request.form["chekt_api_token"],
                    "ip": request.form["chekt_ip"],
                    "port": chekt_port
                },
                "sia": {
                    "ip": request.form["sia_ip"],
                    "port": sia_port,
                    "account_id": request.form["sia_account_id"],
                    "transmitter_id": request.form["sia_transmitter_id"],
                    "encryption_key": request.form["sia_encryption_key"]
                },
                "monitor": {"api_key": request.form["monitor_api_key"]},
                "timezone": request.form["timezone"],
                "door_open_timeout": door_timeout
            }
            save_config(new_config)
            logger.info(f"Config saved: {new_config}")
            flash("Configuration saved", "success")
        except ValueError as e:
            flash(f"Invalid input: {str(e)}", "error")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            flash("Failed to save configuration", "error")
        return redirect(url_for("config"))
    load_config()  # Reload to ensure latest config.yaml values
    logger.info(f"Config data before rendering: {config_data}")
    return render_template("config.html", config=config_data)

@app.route("/get_logs", methods=["GET"])
@login_required
def get_logs():
    try:
        with open("/app/logs/application.log", "r") as f:
            lines = f.readlines()[-150:]  # Last 150 lines
            logs = "".join(lines)
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found"})

@app.route("/check_mqtt_status")
@login_required
def check_mqtt_status():
    return jsonify({"status": "success" if yolink_mqtt_status["connected"] else "error",
                    "message": "YoLink MQTT connection is active." if yolink_mqtt_status["connected"] else "YoLink MQTT connection is inactive."})

@app.route("/check_monitor_mqtt_status")
@login_required
def check_monitor_mqtt_status():
    return jsonify({"status": "success" if monitor_mqtt_status["connected"] else "error",
                    "message": "Monitor MQTT connection is active." if monitor_mqtt_status["connected"] else "Monitor MQTT connection is inactive."})

@app.route("/check_receiver_status")
@login_required
def check_receiver_status():
    receiver_type = config_data.get("receiver_type", "CHEKT")
    if receiver_type == "CHEKT":
        return jsonify({"status": "success", "message": "Receiver is alive."})
    else:  # SIA
        sia_config = config_data.get("sia", {})
        try:
            with socket.create_connection((sia_config["ip"], int(sia_config["port"])), timeout=5):
                return jsonify({"status": "success", "message": "SIA server is alive."})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to connect to SIA server: {str(e)}"})

@app.route("/check_all_statuses")
@login_required
def check_all_statuses():
    return jsonify({
        "yolink": {
            "status": "success" if yolink_mqtt_status["connected"] else "error",
            "message": "YoLink MQTT connection is active." if yolink_mqtt_status["connected"] else "YoLink MQTT connection is inactive."
        },
        "monitor": {
            "status": "success" if monitor_mqtt_status["connected"] else "error",
            "message": "Monitor MQTT connection is active." if monitor_mqtt_status["connected"] else "Monitor MQTT connection is inactive."
        },
        "receiver": check_receiver_status().get_json()
    })

@app.route("/save_mapping", methods=["POST"])
@login_required
def save_mapping():
    mappings = get_mappings().get("mappings", [])
    new_mapping = {
        "yolink_device_id": request.form["yolink_device_id"],
        "chekt_zone": request.form.get("chekt_zone", "")
    }
    mappings = [m for m in mappings if m["yolink_device_id"] != new_mapping["yolink_device_id"]]
    mappings.append(new_mapping)
    redis_client.set("mappings", json.dumps({"mappings": mappings}))
    return jsonify({"status": "success"})

@app.route("/set_door_prop_alarm", methods=["POST"])
@login_required
def set_door_prop_alarm():
    device_id = request.form["device_id"]
    enabled = request.form["enabled"] == "true"
    if device_id in device_data:
        device_data[device_id]["door_prop_alarm"] = enabled
        logger.info(f"Door prop alarm for {device_id} set to {enabled}")
        return jsonify({"status": "success"})
    logger.error(f"Device {device_id} not found for door prop alarm setting")
    return jsonify({"status": "error", "message": "Device not found"}), 404

@app.route("/refresh_yolink_devices")
@login_required
def refresh_yolink_devices():
    load_config()  # Ensure latest config is loaded
    token = config_data['yolink'].get('token')
    if not token:
        token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
        if not token:
            logger.error("No token available after generation attempt")
            return jsonify({"status": "error", "message": "No token available. Please check YoLink credentials."})

    yolink_api = YoLinkAPI(token)
    home_info = yolink_api.get_home_info()
    logger.info(f"Home info response: {home_info}")
    if not home_info or home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve home info: {home_info.get('desc', 'Unknown error')}"})

    home_id = home_info["data"]["id"]
    logger.info(f"Retrieved home_id: {home_id}")
    config_data['home_id'] = home_id  # Store at top-level in config
    save_config(config_data)

    devices = yolink_api.get_device_list()
    logger.info(f"Device list response: {devices}")
    if not devices or devices.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve devices: {devices.get('desc', 'Unknown error')}"})

    existing_devices_data = load_yaml(devices_file) or {}
    existing_devices = {d['deviceId']: d for d in existing_devices_data.get('devices', [])}
    mappings_data = load_yaml(mappings_file) or {'mappings': []}
    mappings_dict = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}

    new_devices = []
    for device in devices["data"]["devices"]:
        device_id = device["deviceId"]
        device_name = device.get('name', f"Device {device_id[-4:]}")
        signal_strength = device.get('loraInfo', {}).get('signal', 'unknown')

        device_data = {
            'deviceId': device_id,
            'name': device_name,
            'state': 'unknown',
            'battery': 'unknown',
            'temperature': 'unknown',
            'humidity': 'unknown',
            'tempLimit': {'max': None, 'min': None},
            'humidityLimit': {'max': None, 'min': None},
            'alarm': {
                'lowBattery': False,
                'lowTemp': False,
                'highTemp': False,
                'lowHumidity': False,
                'highHumidity': False
            },
            'signal': signal_strength,
            'last_seen': 'never'
        }

        if device_id in existing_devices:
            existing_device = existing_devices[device_id]
            device_data.update({
                'state': existing_device.get('state', 'unknown'),
                'battery': existing_device.get('battery', 'unknown'),
                'temperature': existing_device.get('temperature', 'unknown'),
                'humidity': existing_device.get('humidity', 'unknown'),
                'tempLimit': existing_device.get('tempLimit', {'max': None, 'min': None}),
                'humidityLimit': existing_device.get('humidityLimit', {'max': None, 'min': None}),
                'alarm': existing_device.get('alarm', device_data['alarm']),
                'signal': signal_strength,
                'last_seen': existing_device.get('last_seen', 'never')
            })

        if device_id in mappings_dict:
            mapping = mappings_dict[device_id]
            mapping['sia_zone_description'] = device_name
            mapping['sia_signal_strength'] = signal_strength
        else:
            mappings_data['mappings'].append({
                'yolink_device_id': device_id,
                'sia_zone': '',
                'sia_zone_description': device_name,
                'sia_signal_strength': signal_strength,
                'chekt_zone': 'N/A'
            })

        device_data['chekt_zone'] = mappings_dict.get(device_id, {}).get('chekt_zone', 'N/A')
        new_devices.append(device_data)

    devices_data = {"homes": {"id": home_id}, "devices": new_devices}
    save_to_yaml(devices_file, devices_data)
    logger.info(f"Saved devices.yaml with home_id: {home_id}")

    save_to_yaml(mappings_file, mappings_data)

    global mqtt_client_instance
    if mqtt_client_instance:
        mqtt_client_instance.disconnect()
        mqtt_client_instance.loop_stop()
        logger.info("Disconnected existing MQTT client")
    mqtt_thread = threading.Thread(target=run_mqtt_client, daemon=True)
    mqtt_thread.start()

    return jsonify({"status": "success", "message": "YoLink devices refreshed and MQTT client restarted"})

if __name__ == "__main__":
    config_data_full = load_config()
    logger.info(f"Config data after initial load: {config_data_full}")
    config_data.update(config_data_full)
    initialize_default_user()
    max_retries = 5
    retry_delay = 2
    for attempt in range(max_retries):
        try:
            redis_client.ping()
            logger.info("Connected to Redis successfully")
            break
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt == max_retries - 1:
                logger.error(f"Redis not available after {max_retries} attempts: {e}. Exiting.")
                exit(1)
            time.sleep(retry_delay)
    load_devices_to_redis()
    load_mappings_to_redis()
    yolink_config = config_data.get("yolink", {})
    mqtt_config = config_data.get("mqtt", {})
    mqtt_monitor_config = config_data.get("mqtt_monitor", {})
    if yolink_config.get("uaid") and yolink_config.get("secret_key") and mqtt_config.get("url"):
        mqtt_thread = threading.Thread(target=run_mqtt_client, daemon=True)
        mqtt_thread.start()
    else:
        logger.warning("YoLink MQTT not started; configure UAID, Secret Key, and MQTT URL via UI first.")
    if mqtt_monitor_config.get("url"):
        initialize_monitor_mqtt_client()
    else:
        logger.warning("Monitor MQTT not started; configure MQTT Monitor URL via UI first.")
    app.run(host="0.0.0.0", port=5000)