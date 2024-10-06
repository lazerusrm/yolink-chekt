import yaml
import json
import requests
import time
import logging
from flask import Flask, render_template, request, jsonify
import threading
import paho.mqtt.client as mqtt
import os
import socket

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Load configuration from file or memory
config_file = "config.yaml"
device_file = "devices.yaml"
mapping_file = "mappings.yaml"

config_data = {}
log_messages = []  # To collect logs for web view

def add_to_log(message):
    global log_messages
    timestamp = time.strftime("%m/%d/%Y, %I:%M:%S %p")
    log_entry = f"{timestamp}: {message}"
    log_messages.append(log_entry)
    logging.info(log_entry)

def load_config():
    global config_data
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file)
        add_to_log("Configuration loaded.")
    else:
        add_to_log(f"Configuration file '{config_file}' not found.")
    return config_data

def save_config(data):
    global config_data
    config_data = data
    with open(config_file, 'w') as file:
        yaml.dump(data, file)

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

    add_to_log(f"Requesting Yolink token from URL: {url}")
    
    try:
        response = requests.post(url, headers=headers, data=data)
        add_to_log(f"Token response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                add_to_log("Successfully obtained Yolink token.")
                config_data['yolink']['token'] = token
                save_config(config_data)
                return token
            else:
                add_to_log("Failed to obtain Yolink token. Check UAID and Secret Key.")
        else:
            add_to_log(f"Failed to generate Yolink token. Status code: {response.status_code}")
    except Exception as e:
        add_to_log(f"Error generating Yolink token: {str(e)}")

    return None

class YoLinkAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def get_homes(self):
        url = f"{self.base_url}/open/yolink/v2/api"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getGeneralInfo",
            "time": int(time.time() * 1000),
        }

        add_to_log(f"Sending request to get homes: {url}")
        
        try:
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response: {response.status_code} - {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('homes', [])
            elif response.status_code == 401:
                add_to_log("Token expired, regenerating...")
                return None  # Token expired, needs to be regenerated
            else:
                add_to_log(f"Failed to get home info. Status code: {response.status_code}")
                return []
        except Exception as e:
            add_to_log(f"Error getting home info: {str(e)}")
            return []

    def get_device_list(self, home_id):
        url = f"{self.base_url}/open/yolink/v2/api"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getDeviceList",
            "time": int(time.time() * 1000),
            "homeId": home_id
        }

        add_to_log(f"Sending request to get device list: {url}")
        
        try:
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response: {response.status_code} - {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            elif response.status_code == 401:
                add_to_log("Token expired, regenerating...")
                return None  # Token expired, needs to be regenerated
            else:
                add_to_log(f"Failed to get device list. Status code: {response.status_code}")
                return []
        except Exception as e:
            add_to_log(f"Error getting device list: {str(e)}")
            return []

@app.route('/')
def index():
    config = load_config()
    mappings = {}

    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Generate Yolink token if it doesn't exist or is invalid
    token = config.get('yolink', {}).get('token')
    if not token:
        token = generate_yolink_token(config['yolink'].get('uaid', ''), config['yolink'].get('secret_key', ''))

    # Check if required keys are available
    if 'base_url' not in config['yolink']:
        add_to_log("Missing 'base_url' in Yolink configuration.")
        return render_template('index.html', devices=[], mappings=mappings, config=config, error="Configuration Error: 'base_url' key is missing in Yolink configuration.")

    # Query Yolink homes
    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    homes = yolink_api.get_homes()
    if homes is None:
        token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])
        if token:
            yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
            homes = yolink_api.get_homes()
        else:
            add_to_log("Failed to regenerate token for Yolink.")

    return render_template('index.html', homes=homes, mappings=mappings, config=config, logs=log_messages)

@app.route('/get_logs', methods=['GET'])
def get_logs():
    return jsonify(log_messages)

# MQTT Configuration and Callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        add_to_log("Connected to MQTT broker")
        client.subscribe(userdata['topic'])
    else:
        add_to_log(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    add_to_log(f"Received message on topic {msg.topic}: {msg.payload}")
    
    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as mf:
            mappings = yaml.safe_load(mf)
    else:
        mappings = {}

    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload['deviceId']
        state = payload['data']['state']

        if device_id in mappings:
            chekt_zone_id = mappings[device_id]
            add_to_log(f"Triggering CHEKT for device {device_id} in zone {chekt_zone_id} with state {state}")
            trigger_chekt_event(chekt_zone_id, state)
    except Exception as e:
        add_to_log(f"Error processing message: {str(e)}")

def trigger_chekt_event(chekt_zone_id, event_state):
    config = load_config()
    url = f"http://{config['chekt']['ip']}:{config['chekt']['port']}/api/v1/zones/{chekt_zone_id}/events"
    
    headers = {
        'Authorization': f"Bearer {config['chekt']['api_token']}",
        'Content-Type': 'application/json'
    }
    data = {
        "event": event_state,
        "timestamp": int(time.time())
    }

    add_to_log(f"Sending event to CHEKT: {url}")

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code in [200, 202]:
            add_to_log(f"CHEKT zone {chekt_zone_id} updated successfully")
        else:
            add_to_log(f"Failed to update CHEKT zone {chekt_zone_id}. Status code: {response.status_code}")
    except Exception as e:
        add_to_log(f"Error communicating with CHEKT API: {str(e)}")

def run_mqtt_client():
    config = load_config()
    try:
        mqtt_client = mqtt.Client(userdata={"topic": config['mqtt']['topic']})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.connect(config['mqtt']['url'], int(config['mqtt']['port']))
        mqtt_client.loop_forever()
    except socket.gaierror as e:
        add_to_log(f"MQTT connection failed: {str(e)}. Please check the MQTT broker address.")
    except Exception as e:
        add_to_log(f"Unexpected error with MQTT client: {str(e)}")

# Start the MQTT client in a separate thread
mqtt_thread = threading.Thread(target=run_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
