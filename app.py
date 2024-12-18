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

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secure, random 32-byte hex key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='application.log')
logger = logging.getLogger()

# Global variables and configurations
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

# Define a User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires that the `id` property be set

# Implement the user_loader function
@login_manager.user_loader
def load_user(username):
    if username in users_db:
        return User(username)
    return None

# Load configuration
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

# Save configuration
def save_config(data):
    global config_data
    config_data.update(data)
    with open(config_file, 'w') as file:
        yaml.dump(config_data, file)

# Generic load function for other YAML files
def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as yaml_file:
            return yaml.safe_load(yaml_file)
    return {}

# Generic save function for other YAML files
def save_to_yaml(file_path, data):
    with open(file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)

# Helper function to get the monitor API key (deprecated if using MQTT)
def get_monitor_api_key():
    return os.getenv('MONITOR_API_KEY') or config_data.get('monitor', {}).get('api_key')

# Monitor API key (if needed)
monitor_api_key = get_monitor_api_key()

# Remove send_data_to_monitor function if not needed
def send_data_to_monitor(data):
    # Deprecated if using MQTT
    pass

def send_home_info_via_mqtt():
    global mqtt_client_instance

    # Load configuration
    home_id = config_data.get("home_id")
    uaid = config_data.get("yolink", {}).get("uaid")
    secret_key = config_data.get("yolink", {}).get("secret_key")

    if not home_id or not uaid or not secret_key:
        logger.error("Missing home_id, uaid, or secret_key in configuration.")
        return

    # Construct the payload
    payload = {
        "home_id": home_id,
        "uaid": uaid,
        "secret_key": secret_key
    }

    # Define the topic
    topic = f"homes/{home_id}/info"

    try:
        # Publish the message with retain=True
        mqtt_client_instance.publish(topic, json.dumps(payload), retain=True)
        logger.info(f"Sent home info to topic {topic}")
    except Exception as e:
        logger.error(f"Error sending home info via MQTT: {str(e)}")

# YoLink Token Management Functions
def is_token_expired():
    expiry_time = config_data['yolink'].get('token_expiry', 0)
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

                # Store token and expiry time in config
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
        save_config(config_data)  # Save the updated token
        return token
    else:
        logger.error("Failed to generate a new YoLink token.")
        return None

def force_generate_token_and_client():
    config = load_config()

    # Check if token is expired or missing
    if is_token_expired():
        token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
        if not token:
            logger.error("Failed to obtain a valid YoLink token. MQTT client will not start.")
            return None, None
    else:
        token = config['yolink']['token']

    # Always generate a new client ID for MQTT
    client_id = str(uuid.uuid4())
    return token, client_id

def convert_to_timezone(timestamp):
    timezone_name = config_data.get('timezone', 'UTC')
    try:
        target_timezone = pytz.timezone(timezone_name)
    except pytz.UnknownTimeZoneError:
        logger.error(f"Unknown timezone '{timezone_name}' specified in config. Defaulting to UTC.")
        target_timezone = pytz.UTC
    utc_time = datetime.fromtimestamp(timestamp, pytz.UTC)
    return utc_time.astimezone(target_timezone)

def update_device_data(device_id, payload):
    logger.info(f"Updating device data for Device ID: {device_id}")

    # Load the devices.yaml file
    timezone_name = config_data.get('timezone', 'UTC')
    devices_data = load_yaml(devices_file) or {'devices': []}

    now = datetime.now(pytz.timezone(timezone_name)).strftime('%Y-%m-%dT%H:%M:%S')

    # Find the device in devices.yaml based on the device ID
    device_found = False
    for device in devices_data.get('devices', []):
        if device['deviceId'] == device_id:
            device_found = True

            # Update common fields like state, battery, etc.
            device['state'] = payload['data'].get('state', device.get('state', 'unknown'))
            device['battery'] = payload['data'].get('battery', device.get('battery', 'unknown'))

            # Check if temperature and humidity data are present and update accordingly
            if 'temperature' in payload['data']:
                temperature = payload['data'].get('temperature')
                mode = payload['data'].get('mode', 'c')  # Default to Celsius if mode is not present

                if temperature is not None:
                    if mode == 'c':  # Convert from Celsius to Fahrenheit if mode is 'c'
                        device['temperature'] = celsius_to_fahrenheit(temperature)
                    else:
                        device['temperature'] = temperature
                else:
                    device['temperature'] = 'unknown'

            # Handle humidity, if available
            if 'humidity' in payload['data']:
                device['humidity'] = payload['data'].get('humidity', device.get('humidity', 'unknown'))
            else:
                device['humidity'] = 'unknown'

            # Capture the alarm limits for temperature and humidity
            device['tempLimit'] = payload['data'].get('tempLimit', device.get('tempLimit', {'max': None, 'min': None}))
            device['humidityLimit'] = payload['data'].get('humidityLimit', device.get('humidityLimit', {'max': None, 'min': None}))

            # Handle alarm conditions
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

            # Update signal strength from LoRa info
            lora_info = payload['data'].get('loraInfo', {})
            if 'signal' in lora_info:
                device['signal'] = lora_info.get('signal')
            else:
                device['signal'] = 'unknown'

            # Update the last seen timestamp
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

    # Save the updated devices.yaml
    save_to_yaml(devices_file, devices_data)

# Helper function to convert Celsius to Fahrenheit
def celsius_to_fahrenheit(celsius):
    return (celsius * 9/5) + 32

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

# Authentication routes and functions
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logger.info("User is already authenticated; redirecting to index.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')

        # Check for TOTP submission if password already verified
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

        # Handle initial login with username and password
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

        # Retrieve the temporary TOTP secret generated during user creation
        user = temp_user_data.get(username)
        if user:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                # Verification successful - move user to users_db and save to config.yaml
                users_db[username] = user
                config_data['users'] = users_db
                save_config(config_data)

                # Clean up temporary data and confirm success
                temp_user_data.pop(username, None)
                flash('TOTP setup complete. You can now log in.')
                return redirect(url_for('login'))
            else:
                flash('Invalid TOTP code. Please try again.')
                return redirect(url_for('setup_totp', username=username))

    # For GET requests, generate the QR code only if the user hasn’t been verified yet
    if username not in users_db and username in temp_user_data:
        totp_secret = temp_user_data[username]['totp_secret']
        otp_uri = pyotp.TOTP(totp_secret).provisioning_uri(username, issuer_name="YoLink-Monitor")

        # Generate and encode the QR code
        qr = qrcode.make(otp_uri)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        qr_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')

        return render_template('setup_totp.html', qr_code=qr_base64, totp_secret=totp_secret, username=username)

    flash('User not found or already configured.')
    return redirect(url_for('login'))

@app.route('/config')
@login_required
def config():
    # Load devices and mappings from YAML files
    devices_data = load_devices()  # Load devices.yaml
    mappings_data = load_mappings()  # Load mappings.yaml

    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', []) if mappings_data else []

    # Prepare a dictionary to easily access the mappings by device ID
    device_mappings = {m['yolink_device_id']: m for m in mappings}

    # Load configuration for pre-filling the form
    config_data = load_config()

    return render_template('config.html', devices=devices, mappings=device_mappings, config=config_data)

# User creation
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

        # Temporarily store user in temp_user_data until TOTP setup is complete
        temp_user_data[username] = {
            'password': hashed_password,
            'totp_secret': totp_secret
        }

        return redirect(url_for('setup_totp', username=username))

    return render_template('create_user.html')

# Configuration routes and functions
@app.route('/save_config', methods=['POST'])
def save_config_route():
    try:
        # Get the incoming configuration data from the POST request
        new_config_data = request.get_json()

        if not new_config_data:
            return jsonify({"status": "error", "message": "Invalid or empty configuration data."}), 400

        # Log the received configuration for debugging
        logger.debug(f"Received configuration data: {new_config_data}")

        # Load existing configuration
        current_config = load_config()

        # Update the configuration with new values
        current_config.update(new_config_data)

        # Save the updated configuration to the config.yaml file
        save_config(current_config)

        return jsonify({"status": "success", "message": "Configuration saved successfully."})

    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/save_mapping', methods=['POST'])
def save_mapping():
    try:
        # Get the incoming mappings data from the POST request
        new_mappings = request.get_json()
        if not new_mappings or 'mappings' not in new_mappings:
            logger.error(f"Invalid or empty mappings received: {new_mappings}")
            return jsonify({"status": "error", "message": "Invalid mappings data."}), 400

        logger.debug(f"Received new mappings: {new_mappings}")

        # Load the existing mappings from the file
        existing_mappings = load_yaml(mappings_file) or {'mappings': []}

        # Iterate over the new mappings and update or append them to the existing mappings
        for new_mapping in new_mappings['mappings']:
            device_id = new_mapping.get('yolink_device_id')
            existing_mapping = next((m for m in existing_mappings['mappings'] if m['yolink_device_id'] == device_id), None)

            if existing_mapping:
                existing_mapping.update(new_mapping)
            else:
                existing_mappings['mappings'].append(new_mapping)

        # Save the updated mappings back to the file
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

    # Fetch home info
    home_info = yolink_api.get_home_info()
    if not home_info or home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve home info: {home_info.get('desc', 'Unknown error')}"})

    home_id = home_info["data"]["id"]

    # Fetch devices from YoLink API
    devices = yolink_api.get_device_list()
    if not devices or devices.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve devices: {devices.get('desc', 'Unknown error')}"})

    # Load the existing devices.yaml
    existing_devices_data = load_yaml(devices_file) or {}
    existing_devices = {device['deviceId']: device for device in existing_devices_data.get('devices', [])}

    # Load existing mappings to preserve zones
    mappings_data = load_yaml(mappings_file) or {'mappings': []}
    mappings_dict = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}

    # Merge new device list with existing devices to retain dynamic fields
    new_devices = []
    for device in devices["data"]["devices"]:
        device_id = device["deviceId"]

        # Fetch the device name and signal strength from the API response
        device_name = device.get('name', f"Device {device_id[-4:]}")
        signal_strength = device.get('loraInfo', {}).get('signal', 'unknown')

        # Initialize new device structure with default values
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
            # Preserve dynamic fields from existing devices
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

        # Update mappings with SIA fields if they exist, or initialize if not
        if device_id in mappings_dict:
            mapping = mappings_dict[device_id]
            mapping['sia_zone_description'] = device_name  # Map device name to SIA zone description
            mapping['sia_signal_strength'] = signal_strength  # Map signal strength to SIA signal strength
        else:
            mappings_data['mappings'].append({
                'yolink_device_id': device_id,
                'sia_zone': '',  # Populate if needed
                'sia_zone_description': device_name,
                'sia_signal_strength': signal_strength,
                'chekt_zone': 'N/A'
            })

        # Add chekt_zone from mappings if available
        device_data['chekt_zone'] = mappings_dict.get(device_id, {}).get('chekt_zone', 'N/A')

        # Add device to the new devices list
        new_devices.append(device_data)

    # Save the merged device data back to devices.yaml
    data_to_save = {
        "homes": {"id": home_id},
        "devices": new_devices
    }
    save_to_yaml(devices_file, data_to_save)

    # Save updated mappings to mappings.yaml
    save_to_yaml(mappings_file, mappings_data)

    # Restart the MQTT client after refreshing devices
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
        with open('application.log', 'r') as log_file:
            logs = log_file.read()
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

# Load devices from devices.yaml
def load_devices():
    try:
        with open(devices_file, 'r') as file:
            return yaml.safe_load(file) or {}
    except FileNotFoundError:
        return {'devices': []}  # Return empty devices list if file is missing

# Load mappings from mappings.yaml with additional logging
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

# MQTT Configuration and Callbacks for YoLink
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info(f"Successfully connected to YoLink MQTT broker. Subscribing to topic: {userdata['topic']}")
        client.subscribe(userdata['topic'])
    else:
        logger.error(f"Failed to connect to YoLink MQTT broker. Return code: {rc}")

def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")

    try:
        # Parse payload
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')
        event_type = payload.get('event', 'Unknown event').lower()

        # Log essential device information
        if device_id:
            logger.info(f"Device ID: {device_id}, State: {state}, Event Type: {event_type}")
            update_device_data(device_id, payload)

            # Check if the event is an alert or should trigger based on state
            if "alert" in event_type or state in ['open', 'closed', 'alert']:
                device_type = parse_device_type(event_type, payload)

                # Only log when the device event should trigger an action
                if device_type and should_trigger_event(state, device_type):
                    # Validate receiver type and set to CHEKT by default if invalid
                    receiver_type = config_data.get("receiver_type", "CHEKT").upper()
                    if receiver_type not in ["CHEKT", "SIA"]:
                        receiver_type = "CHEKT"

                    # Retrieve zone from mappings without logging the full data
                    mappings_data = load_mappings()
                    mapping = next((m for m in mappings_data.get('mappings', []) if m['yolink_device_id'] == device_id), None)

                    if mapping:
                        # Select the correct zone for the configured receiver type
                        zone = mapping.get('chekt_zone' if receiver_type == "CHEKT" else 'sia_zone')
                        if zone and zone.strip():  # Ensure zone is valid
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

# Helper functions for event handling
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

    # Retrieve receiver_type from config
    receiver_type = config_data.get("receiver_type", "CHEKT").upper()
    if receiver_type not in ["CHEKT", "SIA"]:
        logger.error(f"Invalid receiver type in config: {receiver_type}. Defaulting to CHEKT.")
        receiver_type = "CHEKT"

    # Load mappings and retrieve the correct zone based on receiver type
    mappings_data = load_mappings()
    mapping = next((m for m in mappings_data.get('mappings', []) if m['yolink_device_id'] == device_id), None)

    if not mapping:
        logger.warning(f"No mapping found for device {device_id}")
        return

    # Determine the correct zone based on the receiver type
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

# CHEKT Function, triggers associated zone from device field.
def trigger_chekt_event(device_id, event_description, chekt_zone):
    # Implement your CHEKT event trigger logic here
    pass

# SIA Functions
def send_sia_message(device_id, event_description, zone, sia_config, event_type="BA"):
    # Implement your SIA message sending logic here
    pass

@app.route('/save_zone', methods=['POST'])
def save_zone():
    data = request.get_json()
    device_id = data.get('deviceId')
    zone = data.get('zone')

    if not device_id:
        return jsonify({'status': 'error', 'message': 'Device ID is required.'}), 400

    # Load configuration to determine the receiver type
    config_data = load_config()
    receiver_type = config_data.get("receiver_type", "CHEKT").upper()

    # Load mappings file
    try:
        mappings_data = load_mappings()
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error loading mappings: {str(e)}'}), 500

    # Determine the target key based on receiver type
    target_zone_key = 'chekt_zone' if receiver_type == 'CHEKT' else 'sia_zone'
    target_description_key = 'zone_description' if receiver_type == 'CHEKT' else 'sia_zone_description'
    mappings_list = mappings_data.get('mappings', [])

    # Find any existing mapping for the device
    existing_mapping = next((m for m in mappings_list if m['yolink_device_id'] == device_id), None)

    # Handle case where zone is blank (remove the device from mapping)
    if zone == "":
        if existing_mapping:
            mappings_list.remove(existing_mapping)  # Remove the device mapping if it exists
    else:
        # If zone is specified, update or add it to the mapping
        if existing_mapping:
            existing_mapping[target_zone_key] = zone  # Update the appropriate zone field
            existing_mapping[target_description_key] = data.get('description', 'Unknown Zone')
        else:
            # Add a new mapping with the appropriate zone and description
            mappings_list.append({
                'yolink_device_id': device_id,
                target_zone_key: zone,
                target_description_key: data.get('description', 'Unknown Zone')
            })

    # Save the updated mappings back to mappings.yaml
    mappings_data['mappings'] = mappings_list
    try:
        save_mappings(mappings_data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error saving mappings: {str(e)}'}), 500

    return jsonify({'status': 'success', 'message': f'{receiver_type} zone saved successfully.'}), 200

# Function to save mappings to mappings.yaml
def save_mappings(data):
    try:
        with open(mappings_file, 'w') as yaml_file:
            yaml.dump(data, yaml_file)
        logger.info("Mappings saved successfully.")
    except Exception as e:
        logger.error(f"Error saving mappings: {str(e)}")

# Periodic Tasks
def check_sensor_last_seen():
    # Implement your sensor checking logic here
    pass

def send_monthly_test_signal():
    # Implement your monthly test signal logic here
    pass

def run_mqtt_client():
    global mqtt_client_instance

    config = load_config()

    try:
        # Generate new token and client ID
        token, client_id = force_generate_token_and_client()
        if not token:
            logger.error("Failed to obtain a valid YoLink token. MQTT client will not start.")
            return

        # Load Home ID from devices.yaml
        devices_data = load_yaml(devices_file)
        home_id = devices_data.get('homes', {}).get('id')
        if not home_id:
            logger.error("Home ID not found in devices.yaml. Please refresh YoLink devices.")
            return

        # Fetch MQTT configuration
        mqtt_broker_url = config['mqtt']['url'].replace("mqtt://", "")
        mqtt_broker_port = int(config['mqtt']['port'])
        mqtt_topic = config['mqtt']['topic'].replace("${Home ID}", home_id)

        # Set up the MQTT client and subscribe to the correct topic
        mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": mqtt_topic})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message

        # Set up MQTT credentials with the YoLink token
        mqtt_client.username_pw_set(username=token, password=None)

        # Update the global variable for the MQTT client
        mqtt_client_instance = mqtt_client

        # Connect to the MQTT broker
        logger.info(f"Connecting to MQTT broker at {mqtt_broker_url} on port {mqtt_broker_port}")
        mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)

        # Start the MQTT loop
        mqtt_client.loop_forever()

    except Exception as e:
        logger.error(f"MQTT client encountered an error: {str(e)}")

# Monitor MQTT Client Initialization and Callbacks
def initialize_monitor_mqtt_client():
    global monitor_mqtt_client
    config = load_config()
    mqtt_config = config.get('mqtt_monitor', {})

    mqtt_broker_url = mqtt_config.get('url', 'mqtt://monitor.industrialcamera.com').replace('mqtt://', '')
    mqtt_broker_port = int(mqtt_config.get('port', 1883))
    mqtt_username = mqtt_config.get('username')
    mqtt_password = mqtt_config.get('password')
    mqtt_client_id = mqtt_config.get('client_id', 'monitor_client_id')

    # Set up the MQTT client
    monitor_mqtt_client = mqtt.Client(client_id=mqtt_client_id)
    if mqtt_username and mqtt_password:
        monitor_mqtt_client.username_pw_set(mqtt_username, mqtt_password)

    monitor_mqtt_client.on_connect = on_monitor_mqtt_connect
    monitor_mqtt_client.on_message = on_monitor_mqtt_message

    # Connect to the MQTT broker
    logger.info(f"Connecting to monitor MQTT broker at {mqtt_broker_url}:{mqtt_broker_port}")
    try:
        monitor_mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)
        monitor_mqtt_client.loop_start()
    except Exception as e:
        logger.error(f"Failed to connect to monitor MQTT broker: {str(e)}")

def on_monitor_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to monitor MQTT broker successfully.")
        # Subscribe to topics if you need to receive messages
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
        # Implement your arm logic here
        logger.info("Arming the system as per monitor server command.")
        system_status['armed'] = True
    elif command == 'disarm':
        # Implement your disarm logic here
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

@app.route('/')
@login_required
def index():
    devices_data = load_yaml(devices_file)
    mappings_data = load_yaml(mappings_file)

    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', {}) if mappings_data else {}

    # Prepare a dictionary to easily access the mappings by device ID
    device_mappings = {m['yolink_device_id']: m for m in mappings}

    # Load configuration for pre-filling the form
    config_data = load_config()

    return render_template('index.html', devices=devices, mappings=device_mappings, config=config_data)

if __name__ == "__main__":
    load_config()

    # Start background tasks
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
