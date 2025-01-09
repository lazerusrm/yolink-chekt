# app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import pyotp
import uuid
import yaml
from datetime import datetime, timedelta
import base64
import paho.mqtt.client as mqtt
import json
import requests
import time
import threading
import os
import logging
import qrcode
import io
import secrets
import pytz
import socket  # For SIA TCP communication
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For SIA encryption
from cryptography.hazmat.backends import default_backend
from binascii import hexlify, unhexlify

# ------------------------------------------------------------------------------
# 1. Update Logging Configuration to Use a Relative Path (./logs) by Default
# ------------------------------------------------------------------------------
LOG_DIR = os.getenv("LOG_DIR", "./logs")  # Use environment variable if set, otherwise ./logs
os.makedirs(LOG_DIR, exist_ok=True)

log_file = os.path.join(LOG_DIR, "application.log")

# Configure logging to write to both file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

# ------------------------------------------------------------------------------
# Initialize Flask app
# ------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secure, random 32-byte hex key

# ------------------------------------------------------------------------------
# Global variables and configurations
# ------------------------------------------------------------------------------
mqtt_client_instance = None  # Global variable to store the YoLink MQTT client instance
monitor_mqtt_client = None  # Global variable to store the MQTT client instance for monitor.industrialcamera.com
temp_user_data = {}  # Holds temporary data for users not yet verified
system_status = {'armed': False}  # Track system status (armed/disarmed)

config_file = "config.yaml"
devices_file = "devices.yaml"
mappings_file = "mappings.yaml"

# Global config and users data
config_data = {}
users_db = {}

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if not logged in

# ------------------------------------------------------------------------------
# Define a User class for Flask-Login
# ------------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires that the `id` property be set

# ------------------------------------------------------------------------------
# Implement the user_loader function
# ------------------------------------------------------------------------------
@login_manager.user_loader
def load_user(username):
    if username in users_db:
        return User(username)
    return None

# ------------------------------------------------------------------------------
# Load & Save Configuration
# ------------------------------------------------------------------------------
def load_config():
    global config_data, users_db
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file)
    else:
        config_data = {}

    # Provide default MQTT configuration if not present
    if 'mqtt' not in config_data:
        config_data['mqtt'] = {
            'url': 'mqtt://api.yosmart.com',
            'port': 8003,
            'topic': 'yl-home/${Home ID}/+/report'
        }

    # Provide default monitor MQTT configuration if not present
    if 'mqtt_monitor' not in config_data:
        config_data['mqtt_monitor'] = {
            'url': os.getenv('MONITOR_MQTT_URL', 'mqtt://monitor.industrialcamera.com'),
            'port': int(os.getenv('MONITOR_MQTT_PORT', 1883)),
            'username': os.getenv('MONITOR_MQTT_USERNAME', ''),
            'password': os.getenv('MONITOR_MQTT_PASSWORD', ''),
            'client_id': os.getenv('MONITOR_MQTT_CLIENT_ID', 'monitor_client_id')
        }

    # Load users from config.yaml (if present)
    users_db = config_data.get('users', {})
    return config_data

def save_config(data):
    global config_data
    config_data.update(data)
    with open(config_file, 'w') as file:
        yaml.dump(config_data, file)

def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as yaml_file:
            return yaml.safe_load(yaml_file)
    return {}

def save_to_yaml(file_path, data):
    with open(file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)

# ------------------------------------------------------------------------------
# Helper function to get the monitor API key (deprecated if using MQTT)
# ------------------------------------------------------------------------------
def get_monitor_api_key():
    return os.getenv('MONITOR_API_KEY') or config_data.get('monitor', {}).get('api_key')

monitor_api_key = get_monitor_api_key()

def send_data_to_monitor(data):
    # Deprecated if using MQTT
    pass

# ------------------------------------------------------------------------------
# Example function to send Home info via MQTT
# ------------------------------------------------------------------------------
def send_home_info_via_mqtt():
    global mqtt_client_instance

    home_id = config_data.get("home_id")
    uaid = config_data.get("yolink", {}).get("uaid")
    secret_key = config_data.get("yolink", {}).get("secret_key")

    if not home_id or not uaid or not secret_key:
        logger.error("Missing home_id, uaid, or secret_key in configuration.")
        return

    payload = {
        "home_id": home_id,
        "uaid": uaid,
        "secret_key": secret_key
    }
    topic = f"homes/{home_id}/info"

    try:
        mqtt_client_instance.publish(topic, json.dumps(payload), retain=True)
        logger.info(f"Sent home info to topic {topic}")
    except Exception as e:
        logger.error(f"Error sending home info via MQTT: {str(e)}")

# ------------------------------------------------------------------------------
# YoLink Token Management
# ------------------------------------------------------------------------------
def is_token_expired():
    yolink_data = config_data.get('yolink', {})
    expiry_time = yolink_data.get('token_expiry', 0)
    current_time = time.time()
    return current_time >= expiry_time

def generate_yolink_token(uaid, secret_key):
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret_key}

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")

            if token:
                expiry_time = time.time() + expires_in - 60  # Subtract 60 seconds for early refresh
                config_data['yolink']['token'] = token
                config_data['yolink']['token_expiry'] = expiry_time
                save_config(config_data)
                return token
            else:
                logger.error("Failed to obtain YoLink token. Check UAID and Secret Key.")
        else:
            logger.error(f"Failed to generate YoLink token. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logger.error(f"Error generating YoLink token: {str(e)}")
    return None

def handle_token_expiry():
    token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
    if token:
        config_data['yolink']['token'] = token
        save_config(config_data)
        return token
    else:
        logger.error("Failed to generate a new YoLink token.")
        return None

def force_generate_token_and_client():
    config = load_config()
    if is_token_expired():
        token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
        if not token:
            logger.error("Failed to obtain a valid YoLink token. MQTT client will not start.")
            return None, None
    else:
        token = config['yolink']['token']

    client_id = str(uuid.uuid4())
    return token, client_id

# ------------------------------------------------------------------------------
# Timezone Conversion
# ------------------------------------------------------------------------------
def convert_to_timezone(timestamp):
    timezone_name = config_data.get('timezone', 'UTC')
    try:
        target_timezone = pytz.timezone(timezone_name)
    except pytz.UnknownTimeZoneError:
        logger.error(f"Unknown timezone '{timezone_name}' specified in config. Defaulting to UTC.")
        target_timezone = pytz.UTC
    utc_time = datetime.fromtimestamp(timestamp, pytz.UTC)
    return utc_time.astimezone(target_timezone)

# ------------------------------------------------------------------------------
# Device Data Updates
# ------------------------------------------------------------------------------
def update_device_data(device_id, payload):
    logger.info(f"Updating device data for Device ID: {device_id}")

    timezone_name = config_data.get('timezone', 'UTC')
    devices_data = load_yaml(devices_file) or {'devices': []}
    now = datetime.now(pytz.timezone(timezone_name)).strftime('%Y-%m-%dT%H:%M:%S')

    device_found = False
    for device in devices_data.get('devices', []):
        if device['deviceId'] == device_id:
            device_found = True
            device['state'] = payload['data'].get('state', device.get('state', 'unknown'))
            device['battery'] = payload['data'].get('battery', device.get('battery', 'unknown'))

            # Temperature / Humidity
            if 'temperature' in payload['data']:
                temperature = payload['data'].get('temperature')
                mode = payload['data'].get('mode', 'c')
                if temperature is not None:
                    if mode == 'c':
                        device['temperature'] = celsius_to_fahrenheit(temperature)
                    else:
                        device['temperature'] = temperature
                else:
                    device['temperature'] = 'unknown'

            if 'humidity' in payload['data']:
                device['humidity'] = payload['data'].get('humidity', device.get('humidity', 'unknown'))
            else:
                device['humidity'] = 'unknown'

            device['tempLimit'] = payload['data'].get('tempLimit', device.get('tempLimit', {'max': None, 'min': None}))
            device['humidityLimit'] = payload['data'].get('humidityLimit', device.get('humidityLimit', {'max': None, 'min': None}))

            # Alarms
            if 'alarm' in payload['data']:
                alarm_data = payload['data'].get('alarm', {})
                device['alarm'] = {
                    'lowBattery': alarm_data.get('lowBattery', False),
                    'lowTemp': alarm_data.get('lowTemp', False),
                    'highTemp': alarm_data.get('highTemp', False),
                    'lowHumidity': alarm_data.get('lowHumidity', False),
                    'highHumidity': alarm_data.get('highHumidity', False),
                }
            else:
                device['alarm'] = {
                    'lowBattery': False,
                    'lowTemp': False,
                    'highTemp': False,
                    'lowHumidity': False,
                    'highHumidity': False,
                }

            # Signal Strength
            lora_info = payload['data'].get('loraInfo', {})
            if 'signal' in lora_info:
                device['signal'] = lora_info.get('signal')
            else:
                device['signal'] = 'unknown'

            # Last seen
            device['last_seen'] = now

            # Prepare the data to send to the monitoring server
            device_data = {
                "home_id": config_data.get('home_id', 'UNKNOWN_HOME_ID'),
                "device_id": device_id,
                "sensor_data": {
                    "temperature": device.get('temperature'),
                    "humidity": device.get('humidity'),
                    "state": device.get('state'),
                    "last_seen": device['last_seen'],
                    "signal": device.get('signal'),
                },
                "configuration": config_data,
                "devices": devices_data,
            }

            # Publish device data to monitor MQTT broker
            trigger_monitor_event(device_id, "Device Data Updated", device_data)
            break

    if not device_found:
        logger.warning(f"Device {device_id} not found in devices.yaml.")

    save_to_yaml(devices_file, devices_data)

def celsius_to_fahrenheit(celsius):
    return (celsius * 9/5) + 32

# ------------------------------------------------------------------------------
# YoLink API Class
# ------------------------------------------------------------------------------
class YoLinkAPI:
    def __init__(self, token):
        self.base_url = "https://api.yosmart.com/open/yolink/v2/api"
        self.token = token

    def get_home_info(self):
        url = self.base_url
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getGeneralInfo",
            "time": int(time.time() * 1000)
        }

        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get home info. Status code: {response.status_code}, Response: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error retrieving home info: {str(e)}")
            return None

    def get_device_list(self):
        url = self.base_url
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getDeviceList",
            "time": int(time.time() * 1000)
        }

        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get device list. Status code: {response.status_code}, Response: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error retrieving device list: {str(e)}")
            return None

# ------------------------------------------------------------------------------
# Authentication Routes
# ------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logger.info("User is already authenticated; redirecting to index.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')

        # TOTP step
        if session.get('password_verified') == username:
            user = users_db.get(username)
            if user and 'totp_secret' in user:
                totp = pyotp.TOTP(user['totp_secret'])
                if totp.verify(totp_code):
                    login_user(User(username), remember=True)
                    session.pop('password_verified', None)
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('index'))
                else:
                    flash('Invalid TOTP code. Please try again.')
                    return render_template('login.html', totp_required=True, username=username)

        # Initial login with username/password
        if username and username in users_db:
            user = users_db[username]
            if bcrypt.check_password_hash(user['password'], password):
                session['password_verified'] = username
                return render_template('login.html', totp_required=True, username=username)
            else:
                flash('Invalid username or password.')
        else:
            flash('User does not exist. Please create a new user.')

    return render_template('login.html', totp_required=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('password_verified', None)
    return redirect(url_for('login'))

@app.route('/setup_totp/<username>', methods=['GET', 'POST'])
def setup_totp(username):
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        user = temp_user_data.get(username)
        if user:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                users_db[username] = user
                config_data['users'] = users_db
                save_config(config_data)
                temp_user_data.pop(username, None)
                flash('TOTP setup complete. You can now log in.')
                return redirect(url_for('login'))
            else:
                flash('Invalid TOTP code. Please try again.')
                return redirect(url_for('setup_totp', username=username))

    # Generate the QR code for TOTP
    if username not in users_db and username in temp_user_data:
        totp_secret = temp_user_data[username]['totp_secret']
        otp_uri = pyotp.TOTP(totp_secret).provisioning_uri(username, issuer_name="YoLink-Monitor")

        qr = qrcode.make(otp_uri)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        qr_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')

        return render_template('setup_totp.html', qr_code=qr_base64, totp_secret=totp_secret, username=username)

    flash('User not found or already configured.')
    return redirect(url_for('login'))

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db or username in temp_user_data:
            flash('User already exists. Please log in.')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        totp_secret = pyotp.random_base32()

        temp_user_data[username] = {
            'password': hashed_password,
            'totp_secret': totp_secret
        }

        return redirect(url_for('setup_totp', username=username))

    return render_template('create_user.html')

# ------------------------------------------------------------------------------
# Configuration Routes
# ------------------------------------------------------------------------------
@app.route('/config')
@login_required
def config():
    devices_data = load_devices()
    mappings_data = load_mappings()
    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', []) if mappings_data else []

    device_mappings = {m['yolink_device_id']: m for m in mappings}
    config_data = load_config()

    return render_template('config.html', devices=devices, mappings=device_mappings, config=config_data)

@app.route('/save_config', methods=['POST'])
def save_config_route():
    try:
        new_config_data = request.get_json()
        if not new_config_data:
            return jsonify({"status": "error", "message": "Invalid or empty configuration data."}), 400

        logger.debug(f"Received configuration data: {new_config_data}")
        current_config = load_config()
        current_config.update(new_config_data)
        save_config(current_config)
        return jsonify({"status": "success", "message": "Configuration saved successfully."})
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/save_mapping', methods=['POST'])
def save_mapping():
    try:
        new_mappings = request.get_json()
        if not new_mappings or 'mappings' not in new_mappings:
            logger.error(f"Invalid or empty mappings received: {new_mappings}")
            return jsonify({"status": "error", "message": "Invalid mappings data."}), 400

        logger.debug(f"Received new mappings: {new_mappings}")
        existing_mappings = load_yaml(mappings_file) or {'mappings': []}

        for new_mapping in new_mappings['mappings']:
            device_id = new_mapping.get('yolink_device_id')
            existing_mapping = next((m for m in existing_mappings['mappings'] if m['yolink_device_id'] == device_id), None)
            if existing_mapping:
                existing_mapping.update(new_mapping)
            else:
                existing_mappings['mappings'].append(new_mapping)

        save_to_yaml(mappings_file, existing_mappings)
        logger.debug(f"Updated mappings: {existing_mappings}")
        return jsonify({"status": "success", "message": "Mapping saved successfully."})
    except Exception as e:
        logger.error(f"Error in save_mapping: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/refresh_yolink_devices', methods=['GET'])
def refresh_yolink_devices():
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    yolink_api = YoLinkAPI(token)
    home_info = yolink_api.get_home_info()
    if not home_info or home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve home info: {home_info.get('desc', 'Unknown error')}"})

    home_id = home_info["data"]["id"]
    devices = yolink_api.get_device_list()
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
                'signal': existing_device.get('signal', signal_strength),
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

    data_to_save = {"homes": {"id": home_id}, "devices": new_devices}
    save_to_yaml(devices_file, data_to_save)
    save_to_yaml(mappings_file, mappings_data)

    if mqtt_client_instance:
        mqtt_client_instance.disconnect()
        mqtt_client_instance.loop_stop()

    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()

    return jsonify({"status": "success", "message": "YoLink devices refreshed and MQTT client restarted."})

@app.route('/get_logs', methods=['GET'])
def get_logs():
    try:
        with open(log_file, 'r') as lf:
            logs = lf.read()
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found."})

@app.route('/check_mqtt_status', methods=['GET'])
def check_mqtt_status():
    global mqtt_client_instance
    try:
        if mqtt_client_instance and mqtt_client_instance.is_connected():
            return jsonify({"status": "success", "message": "MQTT connection is active."})
        else:
            return jsonify({"status": "error", "message": "MQTT connection is inactive."})
    except Exception as e:
        logger.error(f"Error checking MQTT status: {str(e)}")
        return jsonify({"status": "error", "message": "Error checking MQTT status."})

@app.route('/get_sensor_data', methods=['GET'])
def get_sensor_data():
    devices_data = load_devices()
    mappings_data = load_mappings()

    devices = devices_data.get('devices', [])
    device_mappings = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}

    all_sensors = []
    for sensor in devices:
        device_id = sensor.get('deviceId')
        mapping = device_mappings.get(device_id, {})
        chekt_zone = mapping.get('chekt_zone', 'N/A')
        last_seen = sensor.get('last_seen', 'Unknown')

        all_sensors.append({
            'deviceId': device_id,
            'name': sensor.get('name', 'Unknown'),
            'state': sensor.get('state', 'Unknown'),
            'battery': sensor.get('battery', 'Unknown'),
            'temperature': sensor.get('temperature', 'Unknown'),
            'humidity': sensor.get('humidity', 'Unknown'),
            'signal': sensor.get('signal', 'Unknown'),
            'last_seen': last_seen,
            'chekt_zone': chekt_zone
        })

    return jsonify({'devices': all_sensors})

def load_devices():
    try:
        with open(devices_file, 'r') as file:
            return yaml.safe_load(file) or {}
    except FileNotFoundError:
        return {'devices': []}

def load_mappings():
    try:
        with open(mappings_file, 'r') as yaml_file:
            mappings_data = yaml.safe_load(yaml_file)
            logger.info(f"Loaded mappings data: {mappings_data}")
            return mappings_data
    except Exception as e:
        logger.error(f"Error loading mappings: {str(e)}")
        return {"mappings": [], "chekt_mappings": [], "sia_mappings": []}

@app.route('/config.html')
@login_required
def config_html():
    devices_data = load_devices()
    mappings_data = load_mappings()
    devices = devices_data.get('devices', [])
    device_mappings = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}
    config_data = load_config()
    return render_template('config.html', devices=devices, mappings=device_mappings, config=config_data)

# ------------------------------------------------------------------------------
# MQTT Configuration and Callbacks for YoLink
# ------------------------------------------------------------------------------
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info(f"Successfully connected to YoLink MQTT broker. Subscribing to topic: {userdata['topic']}")
        client.subscribe(userdata['topic'])
    else:
        logger.error(f"Failed to connect to YoLink MQTT broker. Return code: {rc}")

def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')
        event_type = payload.get('event', 'Unknown event').lower()

        if device_id:
            logger.info(f"Device ID: {device_id}, State: {state}, Event Type: {event_type}")
            update_device_data(device_id, payload)

            if "alert" in event_type or state in ['open', 'closed', 'alert']:
                device_type = parse_device_type(event_type, payload)
                if device_type and should_trigger_event(state, device_type):
                    receiver_type = config_data.get("receiver_type", "CHEKT").upper()
                    if receiver_type not in ["CHEKT", "SIA"]:
                        receiver_type = "CHEKT"

                    mappings_data = load_mappings()
                    mapping = next((m for m in mappings_data.get('mappings', []) if m['yolink_device_id'] == device_id), None)

                    if mapping:
                        zone = mapping.get('chekt_zone' if receiver_type == "CHEKT" else 'sia_zone')
                        if zone and zone.strip():
                            logger.info(f"Triggering {receiver_type} alert in zone {zone} for device {device_id}")
                            trigger_alert(device_id, state, device_type)
                        else:
                            logger.warning(f"No valid zone for device {device_id} with receiver {receiver_type}. Skipping trigger.")
                    else:
                        logger.warning(f"No mapping found for device {device_id}")
                else:
                    logger.info(f"No triggering event for device {device_id}")
            else:
                logger.debug(f"Non-alert event received for device {device_id}. State updated only.")
        else:
            logger.warning("Message received without device ID.")
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

def parse_device_type(event_type, payload):
    if "motionsensor" in event_type.lower():
        return 'motion'
    elif "doorsensor" in event_type.lower():
        return 'door_contact'
    elif "leaksensor" in event_type.lower():
        return 'leak_sensor'
    return None

def should_trigger_event(state, device_type):
    if device_type == 'door_contact' and state in ['open', 'closed']:
        return True
    elif device_type == 'motion' and state == 'alert':
        return True
    elif device_type == 'leak_sensor' and state == 'alert':
        return True
    return False

def map_state_to_event(state, device_type):
    if device_type == 'door_contact':
        if state == 'open':
            return "Door Opened"
        elif state == 'closed':
            return "Door Closed"
    elif device_type == 'motion':
        if state == 'alert':
            return "Motion Detected"
    elif device_type == 'leak_sensor':
        if state == 'alert':
            return "Water Leak Detected"
    return "Unknown Event"

def get_zone(device_id):
    mappings_data = load_yaml(mappings_file)
    mappings = mappings_data.get('mappings', [])
    mapping = next((m for m in mappings if m['yolink_device_id'] == device_id), None)
    if mapping:
        return mapping.get('chekt_zone') or mapping.get('sia_zone')
    return None

def trigger_alert(device_id, state, device_type):
    event_description = map_state_to_event(state, device_type)
    receiver_type = config_data.get("receiver_type", "CHEKT").upper()
    if receiver_type not in ["CHEKT", "SIA"]:
        logger.error(f"Invalid receiver type in config: {receiver_type}. Defaulting to CHEKT.")
        receiver_type = "CHEKT"

    mappings_data = load_mappings()
    mapping = next((m for m in mappings_data.get('mappings', []) if m['yolink_device_id'] == device_id), None)
    if not mapping:
        logger.warning(f"No mapping found for device {device_id}")
        return

    if receiver_type == "CHEKT":
        chekt_zone = mapping.get('chekt_zone')
        if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
            logger.info(f"Triggering CHEKT event in zone {chekt_zone} for device {device_id}")
            trigger_chekt_event(device_id, event_description, chekt_zone)
        else:
            logger.warning(f"No valid CHEKT zone found for device {device_id}. Mapping details: {mapping}")

    elif receiver_type == "SIA":
        sia_zone = mapping.get('sia_zone')
        sia_config = config_data.get('sia', {})
        if sia_zone and sia_zone.strip() and sia_zone != 'N/A':
            logger.info(f"Sending SIA event in zone {sia_zone} for device {device_id}")
            send_sia_message(device_id, event_description, sia_zone, sia_config)
        else:
            logger.warning(f"No valid SIA zone found for device {device_id}. Mapping details: {mapping}")
    else:
        logger.error(f"Unknown receiver type: {receiver_type}")

def trigger_chekt_event(device_id, event_description, chekt_zone, mapping=None):
    """
    Triggers an event on the CHEKT server for a specific zone.

    Parameters:
    - device_id (str): The ID of the device triggering the event.
    - event_description (str): Description of the event.
    - chekt_zone (str): The default zone to trigger the event in.
    - mapping (dict, optional): Mapping information for the device.
    """
    try:
        # Load CHEKT configuration
        chekt_config = config_data.get('chekt', {})
        ip = chekt_config.get('ip')
        port = chekt_config.get('port')
        api_token = chekt_config.get('api_token')

        # Validate CHEKT configuration
        if not ip or not port:
            logger.error("CHEKT IP or Port not configured or missing in config.yaml.")
            return

        if not api_token:
            logger.error("CHEKT API token missing from configuration. Cannot trigger CHEKT event.")
            return

        # Determine the appropriate CHEKT zone
        if mapping and mapping.get('chekt_zone') and mapping['chekt_zone'] != 'N/A':
            chekt_zone = mapping['chekt_zone']
            logger.debug(f"Using mapped CHEKT zone: {chekt_zone} for device {device_id}")
        else:
            logger.debug(f"Using default CHEKT zone: {chekt_zone} for device {device_id}")

        # Construct the API URL using the determined chekt_zone
        chekt_api_url = f"http://{ip}:{port}/api/v1/zones/{chekt_zone}/events"

        # Basic authentication setup
        auth_string = f"apikey:{api_token}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/json"
        }

        # Prepare the payload
        chekt_payload = {
            "event_description": event_description
        }

        logger.info(f"Attempting to post event to CHEKT at URL: {chekt_api_url} with payload: {chekt_payload}")

        # Send the POST request to CHEKT
        response = requests.post(chekt_api_url, headers=headers, json=chekt_payload, timeout=10)

        # Check if the response is JSON
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            response_data = response.json()
            if response.status_code in [200, 202]:
                logger.info(f"Success: Event triggered on zone '{chekt_zone}' for device '{device_id}'. Response: {response_data}")
            else:
                logger.error(f"Failed to trigger event on zone '{chekt_zone}' for device '{device_id}'. "
                             f"Status code: {response.status_code}, Response: {response_data}")
        else:
            if response.status_code in [200, 202]:
                logger.info(f"Event triggered on zone '{chekt_zone}' for device '{device_id}', but response is not JSON. Response: {response.text}")
            else:
                logger.error(f"Failed to trigger event on zone '{chekt_zone}' for device '{device_id}'. "
                             f"Status code: {response.status_code}, Response text: {response.text}")

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while triggering CHEKT event for device '{device_id}': {str(e)}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error while parsing CHEKT event response for device '{device_id}': {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in trigger_chekt_event for device '{device_id}': {str(e)}")

def send_sia_message(device_id, event_description, zone, sia_config, event_type="BA"):
    """
    Send a SIA DC-09 compliant message to the central monitoring station.
    
    Args:
        device_id (str): ID of the YoLink device.
        event_description (str): Description of the event.
        zone (str): Zone number associated with the event.
        sia_config (dict): Configuration dictionary with SIA settings.
        event_type (str): Type of SIA event, default is "BA" (Burglary Alarm).
    """
    try:
        # Retrieve required SIA configuration parameters
        account_id = sia_config.get('account_id')
        transmitter_id = sia_config.get('transmitter_id')
        encryption_key_hex = sia_config.get('encryption_key', '')
        sia_ip = sia_config.get('ip')
        sia_port = int(sia_config.get('port', 0))

        if not all([sia_ip, sia_port, account_id, transmitter_id]):
            logger.error("SIA configuration is incomplete.")
            return

        # Create the SIA message
        contact_id = event_type  # "BA" for burglary alarms, "OA" for Open Alarm, "CA" for Close Alarm, etc.

        # Construct the SIA message
        message = f'"{account_id}" {transmitter_id} {contact_id} {zone} {event_description}\r\n'

        # Encrypt the message if an encryption key is provided
        if encryption_key_hex:
            encryption_key = unhexlify(encryption_key_hex)
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(b'\x00' * 16), backend=default_backend())
            encryptor = cipher.encryptor()
            # Pad the message to be a multiple of 16 bytes (AES block size)
            pad_length = 16 - (len(message) % 16)
            padded_message = message + chr(pad_length) * pad_length
            encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()
            final_message = encrypted_message
            logger.debug(f"Encrypted SIA message: {hexlify(encrypted_message).decode()}")
        else:
            final_message = message.encode()
            logger.debug(f"SIA message without encryption: {message.strip()}")

        # Establish TCP connection and send the message
        with socket.create_connection((sia_ip, sia_port), timeout=10) as sock:
            sock.sendall(final_message)
            logger.info(f"SIA message sent to {sia_ip}:{sia_port} for device '{device_id}'.")
    
    except socket.timeout:
        logger.error(f"Timeout while connecting to SIA server at {sia_ip}:{sia_port}.")
    except socket.error as e:
        logger.error(f"Socket error while sending SIA message: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in send_sia_message for device '{device_id}': {str(e)}")

@app.route('/check_chekt_status', methods=['GET'])  # ADDED
def check_chekt_status():
    """
    Attempt to connect to the CHEKT server via TCP to verify that we can reach it.
    """
    config = load_config()
    chekt_config = config.get("chekt", {})
    ip = chekt_config.get("ip")
    port = chekt_config.get("port")

    if not ip or not port:
        logger.error("CHEKT IP or Port not configured or missing in config.yaml.")
        return jsonify({"status": "error", "message": "CHEKT IP/Port not configured."}), 400

    try:
        # Attempt a short TCP connection to verify the CHEKT server is reachable
        with socket.create_connection((ip, int(port)), timeout=5):
            logger.info(f"Successfully connected to CHEKT at {ip}:{port}")
        return jsonify({"status": "success", "message": "Successfully connected to CHEKT server."})
    except socket.timeout:
        logger.error(f"Timeout while connecting to CHEKT server at {ip}:{port}.")
        return jsonify({"status": "error", "message": "Connection to CHEKT server timed out."}), 500
    except socket.error as e:
        logger.error(f"Socket error while connecting to CHEKT server: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to connect to CHEKT server: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error while connecting to CHEKT server: {str(e)}")
        return jsonify({"status": "error", "message": f"Unexpected error: {str(e)}"}), 500

@app.route('/save_zone', methods=['POST'])
def save_zone():
    data = request.get_json()
    device_id = data.get('deviceId')
    zone = data.get('zone')

    if not device_id:
        return jsonify({'status': 'error', 'message': 'Device ID is required.'}), 400

    config_data = load_config()
    receiver_type = config_data.get("receiver_type", "CHEKT").upper()

    try:
        mappings_data = load_mappings()
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error loading mappings: {str(e)}'}), 500

    target_zone_key = 'chekt_zone' if receiver_type == 'CHEKT' else 'sia_zone'
    target_description_key = 'zone_description' if receiver_type == 'CHEKT' else 'sia_zone_description'
    mappings_list = mappings_data.get('mappings', [])

    existing_mapping = next((m for m in mappings_list if m['yolink_device_id'] == device_id), None)

    if zone == "":
        if existing_mapping:
            mappings_list.remove(existing_mapping)
    else:
        if existing_mapping:
            existing_mapping[target_zone_key] = zone
            existing_mapping[target_description_key] = data.get('description', 'Unknown Zone')
        else:
            mappings_list.append({
                'yolink_device_id': device_id,
                target_zone_key: zone,
                target_description_key: data.get('description', 'Unknown Zone')
            })

    mappings_data['mappings'] = mappings_list
    try:
        save_mappings(mappings_data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error saving mappings: {str(e)}'}), 500

    return jsonify({'status': 'success', 'message': f'{receiver_type} zone saved successfully.'}), 200

def save_mappings(data):
    try:
        with open(mappings_file, 'w') as yaml_file:
            yaml.dump(data, yaml_file)
        logger.info("Mappings saved successfully.")
    except Exception as e:
        logger.error(f"Error saving mappings: {str(e)}")

# ------------------------------------------------------------------------------
# Periodic Tasks (If Needed)
# ------------------------------------------------------------------------------
def check_sensor_last_seen():
    # Implement your sensor checking logic here
    pass

def send_monthly_test_signal():
    # Implement your monthly test signal logic here
    pass

# ------------------------------------------------------------------------------
# Main MQTT Client Loop
# ------------------------------------------------------------------------------
def run_mqtt_client():
    global mqtt_client_instance
    config = load_config()
    try:
        token, client_id = force_generate_token_and_client()
        if not token:
            logger.error("Failed to obtain a valid YoLink token. MQTT client will not start.")
            return

        devices_data = load_yaml(devices_file)
        home_id = devices_data.get('homes', {}).get('id')
        if not home_id:
            logger.error("Home ID not found in devices.yaml. Please refresh YoLink devices.")
            return

        mqtt_broker_url = config['mqtt']['url'].replace("mqtt://", "")
        mqtt_broker_port = int(config['mqtt']['port'])
        mqtt_topic = config['mqtt']['topic'].replace("${Home ID}", home_id)

        mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": mqtt_topic})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.username_pw_set(username=token, password=None)

        mqtt_client_instance = mqtt_client
        logger.info(f"Connecting to MQTT broker at {mqtt_broker_url} on port {mqtt_broker_port}")
        mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)
        mqtt_client.loop_forever()

    except Exception as e:
        logger.error(f"MQTT client encountered an error: {str(e)}")

# ------------------------------------------------------------------------------
# Monitor MQTT Client
# ------------------------------------------------------------------------------
def initialize_monitor_mqtt_client():
    global monitor_mqtt_client
    config = load_config()
    mqtt_config = config.get('mqtt_monitor', {})

    mqtt_broker_url = mqtt_config.get('url', 'mqtt://monitor.industrialcamera.com').replace('mqtt://', '')
    mqtt_broker_port = int(mqtt_config.get('port', 1883))
    mqtt_username = mqtt_config.get('username')
    mqtt_password = mqtt_config.get('password')
    mqtt_client_id = mqtt_config.get('client_id', 'monitor_client_id')

    monitor_mqtt_client = mqtt.Client(client_id=mqtt_client_id)
    if mqtt_username and mqtt_password:
        monitor_mqtt_client.username_pw_set(mqtt_username, mqtt_password)

    monitor_mqtt_client.on_connect = on_monitor_mqtt_connect
    monitor_mqtt_client.on_message = on_monitor_mqtt_message

    logger.info(f"Connecting to monitor MQTT broker at {mqtt_broker_url}:{mqtt_broker_port}")
    try:
        monitor_mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)
        monitor_mqtt_client.loop_start()
    except Exception as e:
        logger.error(f"Failed to connect to monitor MQTT broker: {str(e)}")

def on_monitor_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to monitor MQTT broker successfully.")
        client.subscribe('monitor/commands')
    else:
        logger.error(f"Failed to connect to monitor MQTT broker. Return code: {rc}")

def on_monitor_mqtt_message(client, userdata, msg):
    logger.info(f"Received message from monitor MQTT broker on topic {msg.topic}")
    payload = json.loads(msg.payload.decode('utf-8'))
    handle_monitor_mqtt_message(msg.topic, payload)

def handle_monitor_mqtt_message(topic, payload):
    command = payload.get('command')
    if command == 'arm':
        logger.info("Arming the system as per monitor server command.")
        system_status['armed'] = True
    elif command == 'disarm':
        logger.info("Disarming the system as per monitor server command.")
        system_status['armed'] = False
    else:
        logger.warning(f"Unknown command received from monitor server: {command}")

def publish_to_monitor(topic, payload):
    if monitor_mqtt_client:
        full_topic = f"monitor/{topic}"
        message = json.dumps(payload)
        try:
            monitor_mqtt_client.publish(full_topic, message)
            logger.info(f"Published message to monitor MQTT broker on topic {full_topic}")
        except Exception as e:
            logger.error(f"Failed to publish message to monitor MQTT broker: {str(e)}")
    else:
        logger.error("Monitor MQTT client is not initialized.")

def trigger_monitor_event(device_id, event_description, data=None):
    topic = 'events'
    payload = {
        'device_id': device_id,
        'event_description': event_description,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    if data:
        payload.update(data)
    publish_to_monitor(topic, payload)

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
@app.route('/')
@login_required
def index():
    devices_data = load_yaml(devices_file)
    mappings_data = load_yaml(mappings_file)
    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', {}) if mappings_data else {}

    device_mappings = {m['yolink_device_id']: m for m in mappings}
    config_data = load_config()

    return render_template('index.html', devices=devices, mappings=device_mappings, config=config_data)

if __name__ == "__main__":
    load_config()

    # Optionally start background tasks:
    # check_sensor_last_seen()
    # send_monthly_test_signal()

    # Start the MQTT client in a separate thread
    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()

    # Initialize and start the monitor MQTT client
    initialize_monitor_mqtt_client()
    send_home_info_via_mqtt()

    app.run(host='0.0.0.0', port=5000)
