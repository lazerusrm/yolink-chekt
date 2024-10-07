import yaml
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

# Load configuration from file or memory
config_file = "config.yaml"
config_data = {}

# Load configuration
def load_config():
    global config_data
    with open(config_file, 'r') as file:
        config_data = yaml.safe_load(file)
    return config_data

def save_config(data):
    global config_data
    config_data = data
    with open(config_file, 'w') as file:
        yaml.dump(data, file)

def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as yaml_file:
            return yaml.safe_load(yaml_file)
    return {}

def save_to_yaml(file_path, data):
    with open(file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)


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
    This function generates a new MQTT client ID on startup and only generates a new token if the current one is expired.
    """
    logger.info("Checking if a new Yolink token is needed and generating a new MQTT client ID on startup...")
    
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
        existing_mappings = load_yaml('mappings.yaml') or {'mappings': []}
        logger.debug(f"Existing mappings before update: {existing_mappings}")

        # Append new mappings to the existing mappings list
        if 'mappings' in existing_mappings:
            existing_mappings['mappings'].extend(new_mappings['mappings'])
        else:
            existing_mappings['mappings'] = new_mappings['mappings']

        # Save the updated mappings back to the file
        save_to_yaml("mappings.yaml", existing_mappings)
        logger.debug(f"Updated mappings: {existing_mappings}")

        return jsonify({"status": "success", "message": "Mapping saved successfully."})

    except Exception as e:
        logger.error(f"Error in save_mapping: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/refresh_yolink_devices', methods=['GET'])
def refresh_yolink_devices():
    global mqtt_client_instance  # Access the global instance
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    yolink_api = YoLinkAPI(token)

    # Fetch home info
    home_info = yolink_api.get_home_info()
    if not home_info or home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve home info: {home_info.get('desc', 'Unknown error')}"})

    home_id = home_info["data"]["id"]  # Extract the home ID

    # Fetch devices
    devices = yolink_api.get_device_list()
    if not devices or devices.get("code") != "000000":
        return jsonify({"status": "error", "message": f"Failed to retrieve devices: {devices.get('desc', 'Unknown error')}"})

    # Save home_id and devices in devices.yaml
    data_to_save = {
        "homes": {"id": home_id},  # Store home ID here
        "devices": devices["data"]["devices"]
    }
    save_to_yaml("devices.yaml", data_to_save)

    # Restart the MQTT client after successful device refresh
    if mqtt_client_instance:
        logger.info("Stopping existing MQTT client...")
        mqtt_client_instance.disconnect()  # Disconnect the current client
        mqtt_client_instance.loop_stop()  # Stop the current loop

    logger.info("Restarting MQTT client with updated home_id...")
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
    mappings = mappings_data if mappings_data else {}

    return render_template('index.html', devices=devices, mappings=mappings)

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

        if device_id:
            logger.info(f"Device ID: {device_id}, State: {state}")

            # Load the mappings from mappings.yaml
            mappings = load_yaml(config_data['files']['map_file']).get('mappings', [])
            logger.debug(f"Loaded mappings: {mappings}")

            # Clean the device_id for safe comparison
            device_id = device_id.strip()

            # Find the corresponding mapping for the device
            mapping = next((m for m in mappings if m['yolink_device_id'].strip() == device_id), None)

            if mapping:
                chekt_bridge_channel = mapping.get('chekt_zone')  # Use this as the bridge channel
                if chekt_bridge_channel and chekt_bridge_channel.strip():  # Ensure it's not empty
                    chekt_event = mapping.get('chekt_event', 'Unknown Event')
                    logger.info(f"Triggering CHEKT bridge channel {chekt_bridge_channel} for device {device_id} with event {chekt_event}")
                    trigger_chekt_event(chekt_bridge_channel, chekt_event)
                else:
                    logger.info(f"Device {device_id} has no valid chekt_bridge_channel mapping. Skipping.")
            else:
                logger.warning(f"No mapping found for device {device_id}")
        else:
            logger.warning("Received message without device ID.")

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

def trigger_chekt_event(bridge_channel, event_description):
    chekt_api_url = f"http://{config_data['chekt']['ip']}:{config_data['chekt']['port']}/api/v1/channels/{bridge_channel}/events"
    logger.info(f"Attempting to post event to Chekt at URL: {chekt_api_url}")

    # Minimal payload containing only the event description
    chekt_payload = {
        "event_description": event_description  # Description of the event (e.g., "motion detected", "door opened")
    }

    headers = {
        "Authorization": f"Bearer {config_data['chekt']['api_token']}",
        "Content-Type": "application/json"
    }

    logger.debug(f"Triggering CHEKT event with payload: {chekt_payload}")

    try:
        response = requests.post(chekt_api_url, headers=headers, json=chekt_payload)
        if response.status_code == 200:
            logger.info(f"Successfully triggered event '{event_description}' on bridge channel {bridge_channel}")
        else:
            logger.error(f"Failed to trigger event on bridge channel {bridge_channel}. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logger.error(f"Error while triggering CHEKT event: {str(e)}")

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
            mappings = load_yaml(config_data['files']['map_file']).get('mappings', [])
            logger.debug(f"Loaded mappings: {mappings}")

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
    config = load_config()
    try:
        # Force new token and client ID
        token, client_id = force_generate_token_and_client()
        if not token:
            logger.error("Failed to obtain a valid Yolink token. MQTT client will not start.")
            return  # Exit if token generation fails

        # Fetch the Home ID from the devices.yaml file
        devices_data = load_yaml(config['files']['device_file'])
        home_id = devices_data.get('homes', {}).get('id')

        if not home_id:
            logger.error("Home ID not found in devices.yaml. Please refresh YoLink devices.")
            return  # Exit if no Home ID is found

        # Create the MQTT client and set up callbacks
        mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": f"yl-home/{home_id}/+/report"})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message

        # Log the client ID, token, and Home ID being used for debugging
        logger.info(f"MQTT Client ID: {client_id}")
        logger.info(f"MQTT Access Token (truncated): {token[:10]}...")
        logger.info(f"Subscribing to MQTT topic: yl-home/{home_id}/+/report")

        # Set up the MQTT credentials with the Yolink token
        mqtt_client.username_pw_set(username=token, password=None)

        # Connect to the MQTT broker
        mqtt_broker_url = config['mqtt']['url'].replace("mqtt://", "")
        mqtt_broker_port = int(config['mqtt']['port'])
        logger.info(f"Connecting to MQTT broker at {mqtt_broker_url} on port {mqtt_broker_port}")
        mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)

        # Start the MQTT loop
        mqtt_client.loop_forever()

    except Exception as e:
        logger.error(f"MQTT client encountered an error: {str(e)}")


# Start the MQTT client in a separate thread
mqtt_thread = threading.Thread(target=run_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)