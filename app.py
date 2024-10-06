import yaml
import uuid
import paho.mqtt.client as mqtt
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import threading
import paho.mqtt.client as mqtt
import os
import socket
from datetime import datetime
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='application.log')
logger = logging.getLogger()

# Load configuration from file or memory
config_file = "config.yaml"
config_data = {}

def load_config():
    global config_data
    logger.debug(f"Attempting to load configuration from {config_file}")
    
    if os.path.exists(config_file):
        logger.debug(f"Config file {config_file} found.")
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file)
        logger.debug(f"Loaded configuration: {config_data}")
    else:
        logger.error(f"Config file {config_file} not found!")
    
    return config_data

def save_config(data):
    global config_data
    config_data = data
    with open(config_file, 'w') as file:
        yaml.dump(data, file)
        
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
    """
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": uaid,
        "client_secret": secret_key
    }

    logger.debug(f"Sending token request to URL: {url}")
    try:
        response = requests.post(url, headers=headers, data=data)
        logger.debug(f"Token response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")  # Typically in seconds

            if token:
                logger.info("Successfully obtained Yolink token.")
                expiry_time = time.time() + expires_in - 60  # Subtract 60 seconds to renew slightly before actual expiry

                # Store token and expiry time in config
                config_data['yolink']['token'] = token
                config_data['yolink']['token_expiry'] = expiry_time
                save_config(config_data)  # Save the updated token and expiry time

                return token
            else:
                logger.error("Failed to obtain Yolink token. Check UAID and Secret Key.")
        else:
            logger.error(f"Failed to generate Yolink token. Status code: {response.status_code}")
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

class YoLinkAPI:
    def __init__(self, token):
        self.base_url = "https://api.yosmart.com/open/yolink/v2/api"
        self.token = token

    def get_homes(self):
        url = self.base_url  # No need to format, as it's hardcoded now
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getGeneralInfo",
            "time": int(time.time() * 1000),
        }

        logger.debug(f"Sending get_homes request to URL: {url}")
        logger.debug(f"Request Headers: {json.dumps(headers, indent=2)}")
        logger.debug(f"Request Payload: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(url, json=data, headers=headers)
            logger.debug(f"Response Code: {response.status_code}")
            logger.debug(f"Response Body: {response.text}")

            if response.status_code == 200:
                response_data = response.json()
                if response_data.get("desc") == "Invalid request: The token is expired":
                    logger.warning("Token expired, attempting to refresh.")
                    self.token = handle_token_expiry()
                    return self.get_homes()  # Retry after getting a new token
                return response_data.get('data', {}).get('homes', [])
            else:
                logger.error(f"Failed to retrieve homes. Status code: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error retrieving homes: {str(e)}")

        return []

    def get_device_list(self, home_id):
        url = self.base_url  # No need to format
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getDeviceList",
            "time": int(time.time() * 1000),
            "homeId": home_id
        }

        logger.debug(f"Sending get_device_list request to URL: {url}")
        logger.debug(f"Request Headers: {json.dumps(headers, indent=2)}")
        logger.debug(f"Request Payload: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(url, json=data, headers=headers)
            logger.debug(f"Response Code: {response.status_code}")
            logger.debug(f"Response Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            elif response.status_code == 401:
                logger.warning("Unauthorized request. Token may be invalid or expired.")
                self.token = handle_token_expiry()
                return self.get_device_list(home_id)  # Retry after getting a new token
            else:
                logger.error(f"Failed to retrieve device list. Status code: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error retrieving device list: {str(e)}")

        return []

@app.route('/save_mapping', methods=['POST'])
def save_mapping():
    # Logic to handle saving the mappings
    data = request.get_json()
    save_config(data)
    return jsonify({"status": "success", "message": "Mapping saved successfully."})


@app.route('/')
def index():
    # Load device and mapping configurations
    config = load_config()
    mappings = {}

    if 'files' in config and 'map_file' in config['files']:
        # Log the map file location before trying to open it
        logger.debug(f"Loading mappings from {config['files']['map_file']}")
        
        if os.path.exists(config['files']['map_file']):
            with open(config['files']['map_file'], 'r') as mf:
                mappings = yaml.safe_load(mf)
        else:
            logger.error(f"Mappings file {config['files']['map_file']} not found.")
    else:
        logger.error("Configuration Error: 'files' section or 'map_file' key is missing in the configuration.")

    # Generate Yolink token if it doesn't exist
    token = config['yolink'].get('token')
    if not token:
        token = generate_yolink_token(config['yolink'].get('uaid', ''), config['yolink'].get('secret_key', ''))

    # Check if required keys are available
    if 'base_url' not in config['yolink']:
        logger.error("Configuration Error: 'base_url' key is missing in Yolink configuration.")
        return render_template('index.html', devices=[], mappings=mappings, config=config, error="Configuration Error: 'base_url' key is missing in Yolink configuration.")

    # Query Yolink homes
    yolink_api = YoLinkAPI(token)
    homes = yolink_api.get_homes()

    return render_template('index.html', homes=homes, mappings=mappings, config=config)

@app.route('/get_homes', methods=['GET'])
def get_homes():
    # Load device and mapping configurations
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    base_url = config['yolink'].get('base_url')
    if not base_url:
        return jsonify({"status": "error", "message": "'base_url' key is missing in Yolink configuration."})

    yolink_api = YoLinkAPI(token)
    homes = yolink_api.get_homes()

    if homes:
        return jsonify({"status": "success", "data": homes})
    else:
        return jsonify({"status": "error", "message": "Failed to access Yolink API."})
        
@app.route('/test_yolink_api', methods=['GET'])
def test_yolink_api():
    # Load configuration to get token
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    base_url = config['yolink'].get('base_url')
    if not base_url:
        return jsonify({"status": "error", "message": "'base_url' key is missing in Yolink configuration."})

    yolink_api = YoLinkAPI(token)
    homes = yolink_api.get_homes()
    if homes:
        return jsonify({"status": "success", "data": homes})
    else:
        return jsonify({"status": "error", "message": "Failed to access Yolink API."})

@app.route('/test_chekt_api', methods=['GET'])
def test_chekt_api():
    # Load configuration to get CHEKT API settings
    config = load_config()
    chekt_ip = config['chekt'].get('ip')
    chekt_port = config['chekt'].get('port')
    api_token = config['chekt'].get('api_token')

    if not chekt_ip or not chekt_port:
        return jsonify({"status": "error", "message": "CHEKT API configuration (IP or port) is missing."})

    # Try to access the CHEKT API health endpoint to verify the connection
    url = f"http://{chekt_ip}:{chekt_port}/api/v1/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json',
        'Username': 'apikey'  # Fixed value "apikey" as the username
    }

    try:
        logger.debug(f"Testing CHEKT API Connection to URL: {url}")
        logger.debug(f"Request Headers: {json.dumps(headers, indent=2)}")

        response = requests.get(url, headers=headers)
        logger.debug(f"CHEKT API Response Status Code: {response.status_code}")
        logger.debug(f"CHEKT API Response: {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}", "response": response.text})
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
    logger.info(f"Received message on topic {msg.topic}: {msg.payload.decode('utf-8')}")
    
    # Log file path for mappings
    if os.path.exists(config_data['files']['map_file']):
        logger.debug(f"Loading mappings from {config_data['files']['map_file']}")
        with open(config_data['files']['map_file'], 'r') as mf:
            mappings = yaml.safe_load(mf)
    else:
        mappings = {}
        logger.error(f"Mappings file {config_data['files']['map_file']} not found.")
    
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload['deviceId']
        state = payload['data']['state']

        if device_id in mappings:
            chekt_zone_id = mappings[device_id]
            logger.info(f"Triggering CHEKT for device {device_id} in zone {chekt_zone_id} with state {state}")
            trigger_chekt_event(chekt_zone_id, state)
        else:
            logger.warning(f"Device ID {device_id} not found in mappings.")
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")


def trigger_chekt_event(chekt_zone_id, event_state):
    """
    Trigger an event in the CHEKT system based on the zone ID and the event state.
    """
    config = load_config()
    url = f"http://{config['chekt']['ip']}:{config['chekt']['port']}/api/v1/zones/{chekt_zone_id}/events"

    headers = {
        'Authorization': f"Bearer {config['chekt']['api_token']}",
        'Content-Type': 'application/json'
    }

    # Create the payload for the CHEKT API
    data = {
        "event": event_state,  # Send the state received from Yolink
        "timestamp": int(time.time())
    }

    try:
        # Send the event to the CHEKT API
        response = requests.post(url, headers=headers, json=data)
        if response.status_code in [200, 202]:
            logger.info(f"CHEKT zone {chekt_zone_id} updated successfully")
            if response.status_code == 202:
                logger.info(f"Request accepted for processing. Response: {response.text}")
        else:
            logger.error(f"Failed to update CHEKT zone {chekt_zone_id}. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
    except Exception as e:
        logger.error(f"Error communicating with CHEKT API: {str(e)}")

# MQTT Callbacks and Client Handling
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to Yolink MQTT broker")
        client.subscribe(userdata['topic'])  # Subscribe to the topic from the config
    else:
        logger.error(f"Failed to connect, return code {rc}")

# Callback when a message is received
def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}: {msg.payload}")

    if os.path.exists(config_data['files']['map_file']):
        with open(config_data['files']['map_file'], 'r') as mf:
            mappings = yaml.safe_load(mf)
    else:
        mappings = {}

    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload['deviceId']
        state = payload['data']['state']

        if device_id in mappings:
            chekt_zone_id = mappings[device_id]
            logger.info(f"Triggering CHEKT for device {device_id} in zone {chekt_zone_id} with state {state}")
            trigger_chekt_event(chekt_zone_id, state)

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

# Function to start the MQTT client
import uuid  # Step 1: Import the uuid module

def run_mqtt_client():
    config = load_config()
    try:
        # Ensure we have a valid token and refresh if expired
        token = config['yolink'].get('token')
        if not token or is_token_expired():
            logger.info("Generating or refreshing Yolink token")
            token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
            if not token:
                logger.error("Failed to obtain a valid Yolink token. MQTT client will not start.")
                return  # Exit if token generation fails

        # Generate a unique client ID using uuid
        client_id = str(uuid.uuid4())  

        # Create the MQTT client and set up callbacks
        logger.debug(f"Generated Client ID for MQTT connection: {client_id}")
        mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": config['mqtt']['topic']})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message

        # Set up the MQTT credentials with the Yolink token
        logger.debug(f"Using access token for MQTT: {token[:10]}...(truncated)")
        mqtt_client.username_pw_set(username=token, password=None)

        # Connect to the MQTT broker
        mqtt_broker_url = config['mqtt']['url'].replace("mqtt://", "")
        mqtt_broker_port = int(config['mqtt']['port'])
        logger.debug(f"Connecting to MQTT broker at {mqtt_broker_url} on port {mqtt_broker_port}")
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
