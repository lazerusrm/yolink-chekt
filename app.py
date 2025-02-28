import os
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
import json
from config import load_config, save_config, get_user_data, save_user_data
from db import redis_client, ensure_redis_connection
from device_manager import refresh_yolink_devices, get_all_devices
from mappings import get_mappings, save_mapping, save_mappings  # Ensure save_mappings is imported
from yolink_mqtt import run_mqtt_client, connected as yolink_connected
from monitor_mqtt import run_monitor_mqtt, connected as monitor_connected

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/app/logs/application.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

def init_default_user():
    """Create a default admin user if no users exist."""
    if not redis_client.keys("user:*"):
        default_username = "admin"
        default_password = "admin123"
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        user_data = {"password": hashed_password, "force_password_change": True}
        save_user_data(default_username, user_data)

# Ensure Redis connection
if not ensure_redis_connection():
    logger.error("Exiting due to persistent Redis connection failure")
    exit(1)

init_default_user()

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
            new_config = {
                "yolink": {
                    "uaid": request.form["yolink_uaid"],
                    "secret_key": request.form["yolink_secret_key"],
                    "token": config_data["yolink"]["token"],
                    "token_expiry": config_data["yolink"]["token_expiry"]
                },
                "mqtt": {
                    "url": request.form["yolink_url"],
                    "port": int(request.form["yolink_port"]),
                    "topic": request.form["yolink_topic"]
                },
                "mqtt_monitor": {
                    "url": request.form["monitor_mqtt_url"],
                    "port": int(request.form["monitor_mqtt_port"]),
                    "username": request.form["monitor_mqtt_username"],
                    "password": request.form["monitor_mqtt_password"],
                    "client_id": "monitor_client_id"
                },
                "receiver_type": request.form["receiver_type"],
                "chekt": {
                    "api_token": request.form["chekt_api_token"],
                    "ip": request.form["chekt_ip"],
                    "port": int(request.form["chekt_port"])
                },
                "sia": {
                    "ip": request.form["sia_ip"],
                    "port": int(request.form["sia_port"]) if request.form["sia_port"] else "",
                    "account_id": request.form["sia_account_id"],
                    "transmitter_id": request.form["sia_transmitter_id"],
                    "encryption_key": request.form["sia_encryption_key"]
                },
                "monitor": {"api_key": request.form["monitor_api_key"]},
                "timezone": request.form["timezone"],
                "door_open_timeout": int(request.form["door_open_timeout"]),
                "home_id": config_data.get("home_id", ""),
                "supported_timezones": SUPPORTED_TIMEZONES
            }
            save_config(new_config)
            flash("Configuration saved", "success")
        except ValueError as e:
            flash(f"Invalid input: {str(e)}", "error")
        return redirect(url_for("config"))
    return render_template("config.html", config=config_data)

@app.route('/get_config')
@login_required
def get_config():
    config = load_config()
    return jsonify(config)

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

@app.route("/refresh_devices")
@login_required
def refresh_devices():
    refresh_yolink_devices()
    flash("Devices refreshed successfully", "success")
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
    chekt_zone = data.get("chekt_zone", "")
    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400
    save_mapping(device_id, chekt_zone)
    return jsonify({"status": "success"})

@app.route("/set_door_prop_alarm", methods=["POST"])
@login_required
def set_door_prop_alarm():
    data = request.get_json()
    device_id = data.get("device_id")
    enabled = data.get("enabled") == True
    if not device_id:
        return jsonify({"status": "error", "message": "Missing device ID"}), 400
    mappings = get_mappings()
    for mapping in mappings["mappings"]:
        if mapping["yolink_device_id"] == device_id:
            mapping["door_prop_alarm"] = enabled
            break
    else:
        mappings["mappings"].append({
            "yolink_device_id": device_id,
            "chekt_zone": "N/A",
            "door_prop_alarm": enabled
        })
    save_mappings(mappings)  # Use save_mappings from mappings module
    return jsonify({"status": "success"})

@app.route("/get_sensor_data")
@login_required
def get_sensor_data():
    devices = get_all_devices()
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}
    for device in devices:
        mapping = device_mappings.get(device["deviceId"], {})
        device["chekt_zone"] = mapping.get("chekt_zone", "N/A")
        device["door_prop_alarm"] = mapping.get("door_prop_alarm", False)
        device.setdefault("state", "unknown")
        device.setdefault("signal", "unknown")
        device.setdefault("battery", "unknown")
        device.setdefault("last_seen", "never")
        device.setdefault("alarms", {})
        device.setdefault("temperature", "unknown")
        device.setdefault("humidity", "unknown")
    return jsonify({"devices": devices})

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
    return jsonify({
        "status": "success" if yolink_connected else "error",
        "message": "YoLink MQTT connection is active." if yolink_connected else "YoLink MQTT connection is inactive."
    })

@app.route("/check_monitor_mqtt_status")
@login_required
def check_monitor_mqtt_status():
    return jsonify({
        "status": "success" if monitor_connected else "error",
        "message": "Monitor MQTT connection is active." if monitor_connected else "Monitor MQTT connection is inactive."
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
    return jsonify({
        "yolink": {"status": "success" if yolink_connected else "error", "message": "YoLink MQTT Connected" if yolink_connected else "YoLink MQTT Disconnected"},
        "monitor": {"status": "success" if monitor_connected else "error", "message": "Monitor MQTT Connected" if monitor_connected else "Monitor MQTT Disconnected"},
        "receiver": {"status": "success", "message": "Receiver Connected"}
    })

if __name__ == "__main__":
    import threading
    config_data = load_config()
    threading.Thread(target=run_mqtt_client, daemon=True).start()
    threading.Thread(target=run_monitor_mqtt, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)