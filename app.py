from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import pyotp
import uuid
import yaml
from datetime import datetime
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
import base64


mqtt_client_instance = None  # Global variable to store the MQTT client instance
temp_user_data = {}  # Holds temporary data for users not yet verified

app = Flask(__name__)

# Custom b64encode filter for Jinja2
@app.template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8')

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='application.log')
logger = logging.getLogger()

# Fixed file paths
config_file = "config.yaml"
devices_file = "devices.yaml"
mappings_file = "mappings.yaml"

# Global config and users data
config_data = {}
users_db = {}

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if not logged in
app.secret_key = 'your_secret_key_here'  # You should set this to a secure value

# Define a User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires that the `id` property be set

# Implement the user_loader function
@login_manager.user_loader
def load_user(username):
    if username in users_db:
        return User(username)  # Return a User object if the user exists in the "database"
    return None

# Load configuration
def load_config():
    global config_data, users_db
    with open(config_file, 'r') as file:
        config_data = yaml.safe_load(file)
    
# Provide default MQTT configuration if not present
    if 'mqtt' not in config_data:
        config_data['mqtt'] = {
            'url': 'mqtt://api.yosmart.com',
            'port': 8003,
            'topic': 'yl-home/${Home ID}/+/report'
        }

    # Load users from config.yaml (if present)
    users_db = config_data.get('users', {})
    
    return config_data

# Save configuration
def save_config(data):
    global config_data
    config_data.update(data)

    # Ensure MQTT section is populated with defaults if not present
    if 'mqtt' not in config_data:
        config_data['mqtt'] = {
            'url': 'mqtt://api.yosmart.com',
            'port': 8003,
            'topic': 'yl-home/${Home ID}/+/report'
        }
    
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

# Specifically load devices.yaml
def load_devices():
    return load_yaml(devices_file)

# Specifically load mappings.yaml
def load_mappings():
    return load_yaml(mappings_file)

# Specifically save mappings.yaml
def save_mappings(data):
    save_to_yaml(mappings_file, data)

def is_token_expired():
    """
    Check if the token is expired based on the current time and the stored expiry time.
    Returns True if the token has expired, otherwise False.
    """
    expiry_time = config_data['yolink'].get('token_expiry', 0)
    current_time = time.time()
    
    if current_time >= expiry_time:
        logger.info("Yolink token has expired.")
        return True
    else:
        logger.debug(f"Yolink token is still valid. Expiry time: {expiry_time}, Current time: {current_time}")
        return False

def generate_yolink_token(uaid, secret_key):
    """
    Generate the Yolink access token using the UAID and Secret Key.
    This uses the client_credentials grant type as per the YoLink API documentation.
    """
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret_key}

    logger.debug(f"Sending token request to URL: {url} with UAID: {uaid} and Secret Key.")

    try:
        response = requests.post(url, headers=headers, data=data)
        logger.debug(f"Token response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")

            if token:
                logger.info("Successfully obtained Yolink token.")
                expiry_time = time.time() + expires_in - 60  # Subtract 60 seconds for early refresh

                # Store token and expiry time in config
                config_data['yolink']['token'] = token
                config_data['yolink']['token_expiry'] = expiry_time
                save_config(config_data)

                return token
            else:
                logger.error("Failed to obtain Yolink token. Check UAID and Secret Key.")
        else:
            logger.error(f"Failed to generate Yolink token. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logger.error(f"Error generating Yolink token: {str(e)}")
    return None

def handle_token_expiry():
    """
    Handles the token expiry by generating a new one if needed.
    """
    logger.info("Handling token expiry. Generating a new token...")
    token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
    if token:
        config_data['yolink']['token'] = token
        save_config(config_data)  # Save the updated token
        return token
    else:
        logger.error("Failed to generate a new Yolink token.")
        return None

def force_generate_token_and_client():
    """
    This function generates a new MQTT client ID on startup and ensures a valid token is always used.
    It generates a new token if the current one is expired or missing.
    """
    logger.info("Checking if a new Yolink token is needed and generating a new MQTT client ID on startup...")
    
    # Load configuration
    config = load_config()

    # Check if token is expired or missing
    if is_token_expired():
        logger.info("Yolink token is expired or missing. Generating a new token...")
        token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
        if not token:
            logger.error("Failed to obtain a valid Yolink token. MQTT client will not start.")
            return None, None
    else:
        token = config['yolink']['token']
        logger.info("Yolink token is still valid.")

    # Always generate a new client ID for MQTT
    client_id = str(uuid.uuid4())
    logger.debug(f"Generated new Client ID for MQTT: {client_id}")
    
    return token, client_id

def update_device_data(device_id, payload):
    logger.info(f"Updating device data for Device ID: {device_id}")

    # Load the devices.yaml file
    try:
        devices_data = load_yaml(devices_file)
        logger.info(f"Loaded devices.yaml successfully.")
    except Exception as e:
        logger.error(f"Failed to load devices.yaml: {str(e)}")
        return

    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    # Find the device in devices.yaml based on the device ID
    device_found = False
    for device in devices_data.get('devices', []):
        if device['deviceId'] == device_id:
            device_found = True
            logger.info(f"Device {device_id} found in devices.yaml. Updating data...")

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
                        logger.info(f"Temperature converted to Fahrenheit: {device['temperature']} °F")
                    else:
                        device['temperature'] = temperature
                        logger.info(f"Temperature retained in Fahrenheit: {device['temperature']} °F")
                else:
                    device['temperature'] = 'unknown'
                    logger.warning(f"No temperature data for device {device_id}")

            # Handle humidity, if available
            if 'humidity' in payload['data']:
                device['humidity'] = payload['data'].get('humidity', device.get('humidity', 'unknown'))
                logger.info(f"Humidity updated: {device['humidity']}%")
            else:
                device['humidity'] = 'unknown'
                logger.warning(f"No humidity data for device {device_id}")

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
                logger.info(f"Alarm state updated: {device['alarm']}")
            else:
                device['alarm'] = {
                    'lowBattery': False,
                    'lowTemp': False,
                    'highTemp': False,
                    'lowHumidity': False,
                    'highHumidity': False,
                }
                logger.warning(f"No alarm data for device {device_id}")

            # Update signal strength from LoRa info
            lora_info = payload['data'].get('loraInfo', {})
            if 'signal' in lora_info:
                device['signal'] = lora_info.get('signal')
                logger.info(f"Updated signal strength for device {device_id}: {device['signal']}")
            else:
                device['signal'] = 'unknown'
                logger.warning(f"No signal data for device {device_id}")

            # Update the last seen timestamp
            device['last_seen'] = now
            logger.info(f"Updated device data: {device}")
            break

    if not device_found:
        logger.warning(f"Device {device_id} not found in devices.yaml.")

    # Save the updated devices.yaml
    try:
        save_to_yaml(devices_file, devices_data)
        logger.info(f"Devices.yaml updated successfully for Device ID: {device_id}")
    except Exception as e:
        logger.error(f"Failed to save devices.yaml: {str(e)}")

# Helper function to convert Celsius to Fahrenheit
def celsius_to_fahrenheit(celsius):
    return (celsius * 9/5) + 32

def yolink_api_test():
    # Load configuration to get token
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return {"status": "error", "message": "No token available. Please generate a token first."}

    base_url = config['yolink'].get('base_url')
    if not base_url:
        return {"status": "error", "message": "'base_url' key is missing in Yolink configuration."}

    yolink_api = YoLinkAPI(token)
    homes = yolink_api.get_homes()
    if homes:
        return {"status": "success", "data": homes}
    else:
        return {"status": "error", "message": "Failed to access Yolink API."}
        
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
            "time": int(time.time() * 1000)  # Current time in milliseconds
        }

        try:
            response = requests.post(url, json=data, headers=headers)
            logger.debug(f"Response Code: {response.status_code}")
            logger.debug(f"Response Body: {response.text}")

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
            "time": int(time.time() * 1000)  # Current time in milliseconds
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

def create_user(username, password):
    if username in users_db or username in temp_user_data:
        flash('User already exists. Please log in.')
        return None  # Avoid re-creating an existing user

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    totp_secret = pyotp.random_base32()  # Generate TOTP secret

    # Temporarily store user in temp_user_data until TOTP setup is complete
    temp_user_data[username] = {
        'password': hashed_password,
        'totp_secret': totp_secret
    }
    return username

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect already authenticated users
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code', None)

        # If no users exist, prompt for user creation
        if not users_db:
            create_user(username, password)
            flash(f"User {username} created successfully. Please scan the QR code to set up TOTP.")
            return redirect(url_for('setup_totp', username=username))

        # Check if the user exists in users_db
        if username in users_db:
            user = users_db[username]

            # Check if password has already been verified
            if session.get('password_verified') == username:
                # Proceed with TOTP verification
                if 'totp_secret' in user and totp_code:
                    totp = pyotp.TOTP(user['totp_secret'])
                    if totp.verify(totp_code):
                        # TOTP verified, log in the user
                        login_user(User(username))
                        session.pop('password_verified', None)  # Clear session flag
                        return redirect(url_for('index'))
                    else:
                        flash('Invalid TOTP code.')
                else:
                    flash("Please enter your TOTP code.")
                return render_template('login.html', totp_required=True)

            # Verify password if not yet verified
            elif bcrypt.check_password_hash(user['password'], password):
                # Password verified, store verification in session
                session['password_verified'] = username

                # Prompt for TOTP code if setup, otherwise proceed to TOTP setup
                if 'totp_secret' in user:
                    flash("Please enter your TOTP code.")
                    return render_template('login.html', totp_required=True)
                else:
                    flash(f"User {username} needs to complete TOTP setup.")
                    return redirect(url_for('setup_totp', username=username))
            else:
                flash('Invalid username or password.')
        else:
            flash('User does not exist. Please create a new user.')

    # Render the login page without the TOTP field initially
    return render_template('login.html', totp_required=False)
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('password_verified', None)  # Clear any session flags on logout
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
        otp_uri = pyotp.TOTP(totp_secret).provisioning_uri(username, issuer_name="YoLink-CHEKT")

        # Generate and encode the QR code
        qr = qrcode.make(otp_uri)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        qr_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')

        return render_template('setup_totp.html', qr_code=qr_base64, totp_secret=totp_secret, username=username)

    flash('User not found or already configured.')
    return redirect(url_for('login'))

@app.route('/save_chekt_zone', methods=['POST'])
def save_chekt_zone():
    data = request.get_json()
    device_id = data.get('deviceId')
    chekt_zone = data.get('chekt_zone')

    if not device_id:
        return jsonify({'status': 'error', 'message': 'Invalid data provided.'}), 400

    # Load existing mappings
    mappings_data = load_yaml(mappings_file)
    if mappings_data is None:
        mappings_data = {'mappings': []}  # Initialize if mappings.yaml is empty or doesn't exist

    # Find the mapping for the given device_id
    existing_mapping = next(
        (m for m in mappings_data['mappings'] if m['yolink_device_id'] == device_id),
        None
    )

    if existing_mapping:
        if chekt_zone and chekt_zone.strip():
            # Update the existing mapping with the new chekt_zone
            existing_mapping['chekt_zone'] = chekt_zone.strip()
        else:
            # Remove the chekt_zone to deactivate the sensor
            existing_mapping.pop('chekt_zone', None)
    else:
        if chekt_zone and chekt_zone.strip():
            # Create a new mapping entry only if chekt_zone is provided
            new_mapping = {
                'yolink_device_id': device_id,
                'chekt_zone': chekt_zone.strip()
            }
            mappings_data['mappings'].append(new_mapping)
        else:
            # No chekt_zone provided and no existing mapping; nothing to update
            pass

    # Save the updated mappings
    save_to_yaml(mappings_file, mappings_data)

    return jsonify({'status': 'success', 'message': 'CHEKT zone saved successfully.'}), 200

@app.route('/save_config', methods=['POST'])
def save_config_route():
    try:
        # Get the incoming configuration data from the POST request
        config_data = request.get_json()
        
        if not config_data:
            return jsonify({"status": "error", "message": "Invalid or empty configuration data."}), 400
        
        # Log the received configuration for debugging
        logger.debug(f"Received configuration data: {config_data}")
        
        # Save the configuration to the config.yaml file
        save_config(config_data)
        
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
        existing_mappings = load_yaml('mappings.yaml') or {'mappings': [], 'alert_mapping': []}
        
        # Initialize 'mappings' if not present
        if 'mappings' not in existing_mappings:
            existing_mappings['mappings'] = []
        if 'alert_mapping' not in existing_mappings:
            existing_mappings['alert_mapping'] = []

        logger.debug(f"Existing mappings before update: {existing_mappings}")

        # Iterate over the new mappings and update or append them to the existing mappings
        for new_mapping in new_mappings['mappings']:
            device_id = new_mapping.get('yolink_device_id')
            chekt_zone = new_mapping.get('chekt_zone')
            yolink_event = new_mapping.get('yolink_event')
            chekt_alert = new_mapping.get('chekt_alert')

            # Check if the device already exists in the mappings
            existing_mapping = next((m for m in existing_mappings['mappings'] if m['yolink_device_id'] == device_id), None)

            if existing_mapping:
                # Update the existing mapping with the new zone
                existing_mapping.update(new_mapping)  # This updates all fields in new_mapping
            else:
                # Append new device mapping if it doesn't exist
                existing_mappings['mappings'].append(new_mapping)

            # Handle the alert mapping
            if yolink_event and chekt_alert:
                # Check if the event mapping already exists
                existing_alert_mapping = next((a for a in existing_mappings['alert_mapping'] if a['yolink_event'] == yolink_event and a['yolink_device_id'] == device_id), None)
                
                if existing_alert_mapping:
                    # Update the existing alert mapping
                    existing_alert_mapping['chekt_alert'] = chekt_alert
                else:
                    # Append new alert mapping
                    existing_mappings['alert_mapping'].append({
                        'yolink_device_id': device_id,
                        'yolink_event': yolink_event,
                        'chekt_alert': chekt_alert
                    })

        # Save the updated mappings back to the file
        save_to_yaml("mappings.yaml", existing_mappings)
        logger.debug(f"Updated mappings: {existing_mappings}")

        return jsonify({"status": "success", "message": "Mapping saved successfully."})

    except Exception as e:
        logger.error(f"Error in save_mapping: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/get_sensor_data', methods=['GET'])
def get_sensor_data():
    # Load the devices.yaml file directly
    try:
        devices_data = load_yaml(devices_file)
        if devices_data is None:
            devices_data = {'devices': []}
    except Exception as e:
        return jsonify({'error': f'Failed to load devices.yaml: {str(e)}'}), 500

    # Load the mappings to get the chekt_zone
    try:
        mappings_data = load_yaml(mappings_file)
        if mappings_data is None:
            mappings_data = {'mappings': []}
    except Exception as e:
        return jsonify({'error': f'Failed to load mappings.yaml: {str(e)}'}), 500

    # Create a dictionary for quick lookup of chekt_zone by deviceId
    mappings_dict = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}

    # Ensure there is data in the file and the devices list exists
    if 'devices' in devices_data and len(devices_data['devices']) > 0:
        all_sensors = []
        for sensor in devices_data['devices']:
            device_id = sensor.get('deviceId')
            mapping = mappings_dict.get(device_id, {})
            chekt_zone = mapping.get('chekt_zone', 'N/A')

            all_sensors.append({
                'deviceId': device_id,
                'name': sensor.get('name', 'Unknown'),  # Name or fallback to 'Unknown'
                'state': sensor.get('state', 'Unknown'),  # State or 'Unknown'
                'battery': sensor.get('battery', 'Unknown'),  # Battery level
                'temperature': sensor.get('temperature', 'Unknown'),  # Temperature field
                'humidity': sensor.get('humidity', 'Unknown'),  # Humidity field
                'signal': sensor.get('signal', 'Unknown'),  # Signal strength
                'tempLimit': sensor.get('tempLimit', {'min': None, 'max': None}),  # Temperature limits
                'humidityLimit': sensor.get('humidityLimit', {'min': None, 'max': None}),  # Humidity limits
                'alarm': sensor.get('alarm', {  # Alarm data
                    'lowBattery': False,
                    'lowTemp': False,
                    'highTemp': False,
                    'lowHumidity': False,
                    'highHumidity': False
                }),
                'last_seen': sensor.get('last_seen', 'Unknown'),  # Last seen timestamp
                'chekt_zone': chekt_zone  # Add the chekt_zone to the sensor data
            })

        return jsonify({'devices': all_sensors})
    else:
        return jsonify({'error': 'No sensor data available.'}), 404

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

@app.route('/check_chekt_status', methods=['GET'])
def check_chekt_status():
    config = load_config()
    chekt_ip = config['chekt'].get('ip')
    chekt_port = config['chekt'].get('port')
    api_token = config['chekt'].get('api_token')

    if not chekt_ip or not chekt_port:
        return jsonify({"status": "error", "message": "CHEKT API configuration is missing."})

    url = f"http://{chekt_ip}:{chekt_port}/api/v1/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json',
        'Username': 'apikey'
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT server is alive and API key is valid."})
        else:
            return jsonify({"status": "error", "message": "Failed to connect to CHEKT server. Status code: " + str(response.status_code)})
    except Exception as e:
        logger.error(f"Error connecting to CHEKT server: {str(e)}")
        return jsonify({"status": "error", "message": "Error connecting to CHEKT server."})

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
    try:
        existing_devices_data = load_yaml(devices_file)
        if existing_devices_data is None:
            existing_devices_data = {}  # Ensure we have a dictionary to work with
        existing_devices = {device['deviceId']: device for device in existing_devices_data.get('devices', [])}
    except Exception as e:
        logger.error(f"Error loading devices.yaml: {str(e)}")
        existing_devices = {}

    # Load existing mappings to preserve chekt_zone
    try:
        mappings_data = load_yaml(mappings_file)
        if mappings_data is None:
            mappings_data = {'mappings': []}
        mappings_dict = {m['yolink_device_id']: m for m in mappings_data.get('mappings', [])}
    except Exception as e:
        logger.error(f"Error loading mappings.yaml: {str(e)}")
        mappings_dict = {}

    # Merge new device list with existing devices to retain dynamic fields
    new_devices = []
    for device in devices["data"]["devices"]:
        device_id = device["deviceId"]

        # Fetch the device name directly from the API response
        device_name = device.get('name', f"Device {device_id[-4:]}")  # Default to last 4 chars of deviceId if name is missing

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
            'signal': 'unknown',
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
                'signal': existing_device.get('signal', 'unknown'),
                'last_seen': existing_device.get('last_seen', 'never')
            })

        # Ensure signal field is populated in the new device entry (from LoRa data or default)
        device_data['signal'] = device.get('loraInfo', {}).get('signal', device_data.get('signal'))

        # Add chekt_zone from mappings if available
        mapping = mappings_dict.get(device_id)
        if mapping:
            device_data['chekt_zone'] = mapping.get('chekt_zone', 'N/A')
        else:
            device_data['chekt_zone'] = 'N/A'

        # Add device to the new devices list
        new_devices.append(device_data)

    # Save the merged device data back to devices.yaml
    data_to_save = {
        "homes": {"id": home_id},
        "devices": new_devices
    }
    try:
        save_to_yaml(devices_file, data_to_save)
    except Exception as e:
        logger.error(f"Error saving to devices.yaml: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to save devices to devices.yaml"})

    # Restart the MQTT client after refreshing devices
    if mqtt_client_instance:
        mqtt_client_instance.disconnect()
        mqtt_client_instance.loop_stop()

    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()

    return jsonify({"status": "success", "message": "YoLink devices refreshed and MQTT client restarted."})


@app.route('/save_zone_change', methods=['POST'])
def save_zone_change():
    data = request.json
    device_id = data.get('device_id')
    chekt_zone = data.get('chekt_zone')

    mappings_data = load_yaml('mappings.yaml')
    for mapping in mappings_data['mappings']:
        if mapping['yolink_device_id'] == device_id:
            mapping['chekt_zone'] = chekt_zone
            break

    save_yaml('mappings.yaml', mappings_data)
    return jsonify({"status": "success"})

@app.route('/')
@login_required
def index():
    # Attempt to load devices and mappings from YAML files, using fallback data if it fails
    devices = []
    device_mappings = {}
    config_data = {}

    # Gracefully handle errors when loading devices.yaml
    try:
        devices_data = load_yaml('devices.yaml')
        if devices_data is None:
            raise ValueError("devices.yaml is empty or not properly loaded")
        devices = devices_data.get('devices', [])
    except FileNotFoundError:
        logger.warning("devices.yaml file not found, rendering with no devices.")
    except Exception as e:
        logger.warning(f"Failed to load devices.yaml: {str(e)}, rendering with no devices.")

    # Gracefully handle errors when loading mappings.yaml
    try:
        mappings_data = load_yaml('mappings.yaml')
        mappings = mappings_data.get('mappings', {}) if mappings_data else {}
        device_mappings = {m['yolink_device_id']: m for m in mappings}
    except FileNotFoundError:
        logger.warning("mappings.yaml file not found, rendering with no mappings.")
    except Exception as e:
        logger.warning(f"Failed to load mappings.yaml: {str(e)}, rendering with no mappings.")

    # Gracefully handle errors when loading config.yaml
    try:
        config_data = load_config()
    except Exception as e:
        logger.warning(f"Failed to load config: {str(e)}, rendering with default config.")

    # Render the page with the data (even if it's partial or empty)
    return render_template('index.html', devices=devices, mappings=device_mappings, config=config_data)

@app.route('/config.html')
def config():
    # Load devices and mappings from YAML files
    devices_data = load_yaml('devices.yaml')
    mappings_data = load_yaml('mappings.yaml')

    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', {}) if mappings_data else {}

    # Prepare a dictionary to easily access the mappings by device ID
    device_mappings = {m['yolink_device_id']: m for m in mappings}

    # Load configuration for pre-filling the form
    config_data = load_config()

    return render_template('config.html', devices=devices, mappings=device_mappings, config=config_data)

@app.route('/get_homes', methods=['GET'])
def get_homes():
    # Load configuration to get the Yolink token
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    yolink_api = YoLinkAPI(token)

    # Get home info
    home_info = yolink_api.get_home_info()
    if not home_info:
        return jsonify({"status": "error", "message": "Failed to retrieve home info from YoLink API."})

    if home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Error from YoLink API: {home_info.get('desc', 'Unknown error')}"})

    # Get device list for the home
    devices = yolink_api.get_device_list()
    if not devices:
        return jsonify({"status": "error", "message": "Failed to retrieve device list from YoLink API."})

    if devices.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Error retrieving devices: {devices.get('desc', 'Unknown error')}"})

    # Returning both home info and device list
    return jsonify({
        "status": "success",
        "home": home_info["data"],  # Ensure you're accessing the correct data structure
        "devices": devices["data"]["devices"]  # List of devices
    })
        
@app.route('/test_yolink_api', methods=['GET'])
def test_yolink_api():
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    yolink_api = YoLinkAPI(token)

    # Test by calling get_home_info and get_device_list
    home_info = yolink_api.get_home_info()
    if not home_info:
        return jsonify({"status": "error", "message": "Failed to retrieve home info from YoLink API."})

    devices = yolink_api.get_device_list()
    if not devices:
        return jsonify({"status": "error", "message": "Failed to retrieve device list from YoLink API."})

    return jsonify({
        "status": "success",
        "home_info": home_info,
        "devices": devices
    })

@app.route('/test_chekt_api', methods=['GET'])
def test_chekt_api():
    config = load_config()
    chekt_ip = config['chekt'].get('ip')
    chekt_port = config['chekt'].get('port')
    api_token = config['chekt'].get('api_token')

    if not chekt_ip or not chekt_port:
        return jsonify({"status": "error", "message": "CHEKT API configuration (IP or port) is missing."})

    url = f"http://{chekt_ip}:{chekt_port}/api/v1/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json',
        'Username': 'apikey'
    }

    try:
        logger.debug(f"Testing CHEKT API Connection to URL: {url}")
        response = requests.get(url, headers=headers)
        logger.debug(f"CHEKT API Response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}"})
    except Exception as e:
        logger.error(f"Error connecting to CHEKT API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/get_logs', methods=['GET'])
def get_logs():
    try:
        with open('application.log', 'r') as log_file:
            logs = log_file.read()
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found."})
        
# MQTT Configuration and Callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info(f"Successfully connected to MQTT broker. Subscribing to topic: {userdata['topic']}")
        client.subscribe(userdata['topic'])
    else:
        logger.error(f"Failed to connect to MQTT broker. Return code: {rc}")
        
def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")

    try:
        # Log the raw payload first
        logger.info(f"Raw payload: {msg.payload.decode('utf-8')}")

        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')
        event_type = payload.get('event', 'Unknown event').lower()

        logger.info(f"Parsed Device ID: {device_id}, State: {state}, Event Type: {event_type}")

        if device_id:
            logger.info(f"Calling update_device_data for Device ID: {device_id}")

            # Explicitly call update_device_data and log the payload
            update_device_data(device_id, payload)

            # Check if the event is an alert (.Alert) to trigger the system
            if "alert" in event_type:
                device_type = parse_device_type(event_type, payload)
                logger.info(f"Device {device_id} identified as {device_type}")

                if device_type and should_trigger_event(state, device_type):
                    chekt_bridge_channel = get_chekt_zone(device_id)
                    chekt_event = map_state_to_event(state, device_type)

                    if chekt_bridge_channel and chekt_bridge_channel.strip():
                        logger.info(f"Triggering CHEKT bridge channel {chekt_bridge_channel} for device {device_id} with event {chekt_event}")
                        trigger_chekt_event(chekt_bridge_channel, chekt_event)
                    else:
                        logger.info(f"No valid CHEKT bridge channel for device {device_id}. Skipping.")
            else:
                logger.info(f"Received report event: {event_type}, data updated.")
        else:
            logger.warning("Message without device ID.")

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

# Helper function to determine the device type based on event or payload data
def parse_device_type(event_type, payload):
    if "MotionSensor" in event_type:
        return 'motion'
    elif "DoorSensor" in event_type:
        return 'door_contact'
    elif "LeakSensor" in event_type:
        return 'leak_sensor'
    return None

# Helper function to determine if an event should trigger based on state and device type
def should_trigger_event(state, device_type):
    if device_type == 'door_contact' and state in ['open', 'closed']:
        return True
    elif device_type == 'motion' and state == 'alert':
        return True
    elif device_type == 'leak_sensor' and state == 'alert':
        return True
    return False


# Helper function to map state to the appropriate CHEKT event
# Helper function to map state to the appropriate CHEKT event
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

# Helper function to dynamically determine the CHEKT zone for a device
def get_chekt_zone(device_id):
    # Logic to retrieve the correct CHEKT zone for the given device ID
    # For now, this could be hardcoded or pulled from another dynamic source, like a configuration or database
    return "1"  # Example: returning CHEKT zone 1, adjust logic as needed

def trigger_chekt_event(bridge_channel, event_description):
    chekt_api_url = f"http://{config_data['chekt']['ip']}:{config_data['chekt']['port']}/api/v1/channels/{bridge_channel}/events"
    
    # Basic authentication setup
    api_key = config_data['chekt']['api_token']
    auth_header = base64.b64encode(f"apikey:{api_key}".encode()).decode()
    
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/json"
    }
    
    chekt_payload = {
        "target_channel": bridge_channel,
        "event_description": event_description,
    }

    logger.info(f"Attempting to post event to CHEKT at URL: {chekt_api_url} with payload: {chekt_payload}")
    try:
        response = requests.post(chekt_api_url, headers=headers, json=chekt_payload)
        response_data = response.json()  # Parse the response to JSON

        if response.status_code == 200 or response.status_code == 202:
            logger.info(f"Response: {response_data}")
            print(f"Success: Event triggered on bridge channel {bridge_channel}.")
            print(f"Response Data: {json.dumps(response_data, indent=2)}")
        else:
            logger.error(f"Failed to trigger event on bridge channel {bridge_channel}. Status code: {response.status_code}, Response: {response.text}")
            print(f"Error: Failed to trigger event. Status code: {response.status_code}")
            print(f"Response Text: {response.text}")
    except Exception as e:
        logger.error(f"Error while triggering CHEKT event: {str(e)}")
        print(f"Error: {str(e)}")

# MQTT Callbacks and Client Handling
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to Yolink MQTT broker")
        client.subscribe(userdata['topic'])  # Subscribe to the topic from the config
    else:
        logger.error(f"Failed to connect, return code {rc}")

# Callback when a message is received
def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")

    try:
        # Log the raw payload first
        logger.info(f"Raw payload: {msg.payload.decode('utf-8')}")

        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')

        if device_id:
            logger.info(f"Device ID: {device_id}, State: {state}")

            # Update device data in devices.yaml
            logger.info(f"Updating device data for device {device_id}")
            update_device_data(device_id, payload)  # Call function to update the device's data

            # Load the mappings directly from mappings.yaml
            try:
                mappings_data = load_yaml(mappings_file)
                mappings = mappings_data.get('mappings', [])
            except Exception as e:
                logger.error(f"Failed to load mappings.yaml: {str(e)}")
                return  # Exit early if there's an error loading the mappings

            # Find the corresponding mapping for the device in mappings.yaml
            mapping = next((m for m in mappings if m['yolink_device_id'] == device_id), None)

            if mapping:
                chekt_zone = mapping.get('chekt_zone')
                if chekt_zone and chekt_zone.strip():  # Ensure chekt_zone is not empty
                    chekt_event = mapping.get('chekt_event', 'Unknown Event')
                    logger.info(f"Triggering CHEKT for device {device_id} in zone {chekt_zone} with event {chekt_event}")
                    trigger_chekt_event(chekt_zone, chekt_event)
                else:
                    logger.info(f"Device {device_id} has no valid chekt_zone mapping. Skipping.")
            else:
                logger.warning(f"No mapping found for device {device_id}")
        else:
            logger.warning("Received message without device ID.")

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
def test_chekt_api():
    with app.app_context():  # This creates the application context
        response = chekt_api_test()
        print(response)
        return response
                
def run_mqtt_client():
    """
    This function starts the MQTT client with the generated token and client ID.
    """
    global mqtt_client_instance  # Ensure the global variable is used
    
    config = load_config()

    try:
        # Generate new token and client ID
        token, client_id = force_generate_token_and_client()
        if not token:
            logger.error("Failed to obtain a valid Yolink token. MQTT client will not start.")
            return  # Exit if token generation fails

        # Load Home ID from devices.yaml
        devices_data = load_yaml(devices_file)
        home_id = devices_data.get('homes', {}).get('id')
        if not home_id:
            logger.error("Home ID not found in devices.yaml. Please refresh YoLink devices.")
            return  # Exit if no Home ID is found

        # Fetch MQTT configuration
        try:
            mqtt_broker_url = config['mqtt']['url'].replace("mqtt://", "")
            mqtt_broker_port = int(config['mqtt']['port'])
            mqtt_topic = config['mqtt']['topic'].replace("${Home ID}", home_id)
        except KeyError as e:
            logger.error(f"Missing 'mqtt' configuration: {str(e)}")
            return  # Exit if any MQTT configuration is missing

        # Log the MQTT broker details
        logger.debug(f"MQTT Broker URL: {mqtt_broker_url}, Port: {mqtt_broker_port}, Topic: {mqtt_topic}")

        # Set up the MQTT client and subscribe to the correct topic
        mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": mqtt_topic})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message

        # Set up MQTT credentials with the Yolink token
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

def refresh_and_save_devices():
    logger.info("Refreshing YoLink devices on startup...")

    try:
        # Refresh devices by directly calling the function
        refresh_response = refresh_yolink_devices()

        if isinstance(refresh_response, dict) and refresh_response.get('status') == 'success':
            logger.info("YoLink devices refreshed successfully and saved.")
        else:
            logger.error(f"Failed to refresh YoLink devices. Response: {refresh_response}")
    except Exception as e:
        logger.error(f"Error refreshing YoLink devices: {str(e)}")

# Start the MQTT client in a separate thread
mqtt_thread = threading.Thread(target=run_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == "__main__":
    load_config()
    
    # Ensure Flask application context is active
    with app.app_context():
        refresh_and_save_devices()

    app.run(host='0.0.0.0', port=5000)

