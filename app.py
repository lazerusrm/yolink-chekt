import yaml
from datetime import datetime
import base64
import uuid
import paho.mqtt.client as mqtt
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import threading
import os
import logging

mqtt_client_instance = None  # Global variable to store the MQTT client instance

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='application.log')
logger = logging.getLogger()

# Fixed file paths
config_file = "config.yaml"
devices_file = "devices.yaml"
mappings_file = "mappings.yaml"

config_data = {}

# Load configuration
def load_config():
    global config_data
    with open(config_file, 'r') as file:
        config_data = yaml.safe_load(file)
    
    # Provide default MQTT configuration if not present
    if 'mqtt' not in config_data:
        config_data['mqtt'] = {
            'url': 'mqtt://api.yosmart.com',
            'port': 8003,
            'topic': 'yl-home/${Home ID}/+/report'
        }
    return config_data


# Save configuration
def save_config(data):
    global config_data
    
    # Merge incoming data with existing config, so static sections like 'mqtt' remain intact
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
    # Hardcoded path to the devices.yaml file
    file_path = "devices.yaml"

    # Load the devices.yaml file
    devices_data = load_yaml(file_path)

    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    # Find the device in devices.yaml based on the device ID
    for device in devices_data['devices']:
        if device['deviceId'] == device_id:
            # Update the device's state
            device['state'] = payload['data'].get('state', device.get('state', 'unknown'))

            # Update the device's battery if available
            device['battery'] = payload['data'].get('battery', device.get('battery', 'unknown'))

            # Update power-related information if applicable (specific to Outlet)
            if 'power' in payload['data']:
                device['power'] = payload['data'].get('power', device.get('power', 'unknown'))
                device['watt'] = payload['data'].get('watt', device.get('watt', 'unknown'))

            # Convert temperature to Fahrenheit if available
            temperature_c = payload['data'].get('devTemperature')
            if temperature_c is not None:
                device['devTemperature'] = celsius_to_fahrenheit(temperature_c)
            else:
                device['devTemperature'] = device.get('devTemperature', 'unknown')

            # Update signal strength from LoRa info
            lora_info = payload['data'].get('loraInfo', {})
            device['signal'] = lora_info.get('signal', device.get('signal', 'unknown'))

            # Update the last seen timestamp
            device['last_seen'] = now

    # Save the updated devices.yaml
    save_to_yaml(file_path, devices_data)

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
    global mqtt_client_instance
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
    existing_devices_data = load_yaml(devices_file)
    existing_devices = {device['deviceId']: device for device in existing_devices_data.get('devices', [])}

    # Merge new device list with existing devices to retain dynamic fields
    new_devices = []
    for device in devices["data"]["devices"]:
        device_id = device["deviceId"]
        
        if device_id in existing_devices:
            # Preserve dynamic fields (state, battery, etc.)
            existing_device = existing_devices[device_id]
            device['state'] = existing_device.get('state', 'unknown')
            device['battery'] = existing_device.get('battery', 'unknown')
            device['devTemperature'] = existing_device.get('devTemperature', 'unknown')
            device['last_seen'] = existing_device.get('last_seen', 'never')

        # Add device to the new devices list
        new_devices.append(device)

    # Save the merged device data back to devices.yaml
    data_to_save = {
        "homes": {"id": home_id},
        "devices": new_devices
    }
    save_to_yaml("devices.yaml", data_to_save)

    # Restart the MQTT client after refreshing devices
    if mqtt_client_instance:
        mqtt_client_instance.disconnect()
        mqtt_client_instance.loop_stop()

    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()

    return jsonify({"status": "success", "message": "Yolink devices refreshed and MQTT client restarted."})

@app.route('/')
def index():
    # Load devices and mappings from YAML files
    devices_data = load_yaml('devices.yaml')
    mappings_data = load_yaml('mappings.yaml')

    devices = devices_data.get('devices', [])
    mappings = mappings_data.get('mappings', {}) if mappings_data else {}

    # Prepare a dictionary to easily access the mappings by device ID
    device_mappings = {m['yolink_device_id']: m for m in mappings}

    # Load configuration for pre-filling the form
    config_data = load_config()

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
    # Only log basic info about the message received
    logger.info(f"Received message on topic {msg.topic}")

    try:
        # Decode and parse the payload
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')
        event_type = payload.get('event', 'Unknown event').lower()  # Ensure event_type is case-insensitive

        if device_id:
            # Log key information about the device and event
            logger.info(f"Device ID: {device_id}, State: {state}, Event Type: {event_type}")

            # Update device data (for both alerts and reports)
            update_device_data(device_id, payload)

            # Check if the event is an alert (".Alert" events trigger the system)
            if "alert" in event_type:
                device_type = parse_device_type(event_type, payload)

                if device_type:
                    logger.info(f"Device {device_id} identified as {device_type}")

                    # Determine if an event should be triggered based on state and device type
                    if should_trigger_event(state, device_type):
                        chekt_bridge_channel = get_chekt_zone(device_id)  # Retrieve CHEKT zone dynamically
                        chekt_event = map_state_to_event(state, device_type)  # Map state to CHEKT event

                        if chekt_bridge_channel and chekt_bridge_channel.strip():  # Ensure it's not empty
                            logger.info(f"Triggering CHEKT bridge channel {chekt_bridge_channel} for device {device_id} with event {chekt_event}")
                            trigger_chekt_event(chekt_bridge_channel, chekt_event)
                        else:
                            logger.info(f"Device {device_id} has no valid chekt_bridge_channel mapping. Skipping.")
                    else:
                        logger.info(f"State {state} for device {device_id} does not trigger an event. Skipping.")
                else:
                    logger.warning(f"Could not determine device type for {device_id}. Skipping.")
            else:
                logger.info(f"Received a report event ({event_type}). No system trigger, data updated.")
        else:
            logger.warning("Message received without a valid device ID.")

    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON payload: {msg.payload}")
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
def map_state_to_event(state, device_type):
    if device_type == 'door_contact':
        return f"Door {state}"  # e.g., "Door opened" or "Door closed"
    elif device_type == 'motion':
        return "Motion detected"
    elif device_type == 'leak_sensor':
        return "Water leak detected"
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

            # Load the mappings from mappings.yaml
            mappings = load_yaml(mappings_file).get('mappings', [])
            #logger.debug(f"Loaded mappings: {mappings}")

            # Find the corresponding mapping for the device
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

