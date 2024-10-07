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
    This function forces the generation of a new token and a new client ID each time the app starts.
    """
    logger.info("Forcing generation of new Yolink token and MQTT client ID on startup...")
    config = load_config()
    
    # Always generate a new token
    token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
    
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
    # Logic to handle saving the mappings
    data = request.get_json()
    save_config(data)
    return jsonify({"status": "success", "message": "Mapping saved successfully."})

@app.route('/refresh_yolink_devices', methods=['GET'])
def refresh_yolink_devices():
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    yolink_api = YoLinkAPI(token)

    # Fetch homes and devices
    home_info = yolink_api.get_home_info()
    if not home_info or home_info.get("code") != "000000":
        return jsonify({"status": "error", "message": "Failed to retrieve home info."})

    devices = yolink_api.get_device_list()
    if not devices or devices.get("code") != "000000":
        return jsonify({"status": "error", "message": "Failed to retrieve devices."})

    # Store homes and devices in devices.yaml
    data_to_save = {
        "homes": home_info["data"],
        "devices": devices["data"]["devices"]
    }
    save_to_yaml("devices.yaml", data_to_save)

    return jsonify({"status": "success", "message": "Yolink devices refreshed and saved."})

def save_to_yaml(file_path, data):
    with open(file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)

@app.route('/')
def index():
    devices_data = load_yaml('devices.yaml')

    homes = devices_data.get('homes', [])
    devices = devices_data.get('devices', [])

    return render_template('index.html', homes=homes, devices=devices)

def load_yaml(file_path):
    with open(file_path, 'r') as yaml_file:
        return yaml.safe_load(yaml_file)

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

        # Create the MQTT client and set up callbacks
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