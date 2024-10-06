import yaml
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import threading
import paho.mqtt.client as mqtt
import os
import socket

app = Flask(__name__)

# Load configuration from file or memory
config_file = "config.yaml"
device_file = "devices.yaml"
mapping_file = "mappings.yaml"

config_data = {}

def load_config():
    global config_data
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file)
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
    
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                config_data['yolink']['token'] = token
                save_config(config_data)
                return token
            else:
                print("Failed to obtain token, check UAID and Secret Key.")
                return None
        else:
            print(f"Failed to generate Yolink token. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"Error generating Yolink token: {str(e)}")
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

        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 200:
                return response.json().get('data', {}).get('homes', [])
            else:
                print(f"Failed to get home info. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return []
        except Exception as e:
            print(f"Error getting home info: {str(e)}")
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

        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            else:
                print(f"Failed to get device list. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return []
        except Exception as e:
            print(f"Error getting device list: {str(e)}")
            return []

@app.route('/')
def index():
    # Load device and mapping configurations
    config = load_config()
    mappings = {}

    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Generate Yolink token if it doesn't exist
    token = config['yolink'].get('token')
    if not token:
        token = generate_yolink_token(config['yolink'].get('uaid', ''), config['yolink'].get('secret_key', ''))
    
    # Check if required keys are available
    if 'base_url' not in config['yolink']:
        return render_template('index.html', devices=[], mappings=mappings, config=config, error="Configuration Error: 'base_url' key is missing in Yolink configuration.")

    # Query Yolink homes
    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    homes = yolink_api.get_homes()

    return render_template('index.html', homes=homes, mappings=mappings, config=config)

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
    url = f"http://{chekt_ip}:{chekt_port}/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json'
    }

    try:
        print(f"Testing CHEKT API Connection to URL: {url}")
        response = requests.get(url, headers=headers)
        print(f"CHEKT API Response Status Code: {response.status_code}")
        print(f"CHEKT API Response: {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}", "response": response.text})
    except Exception as e:
        print(f"Error connecting to CHEKT API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})


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

    # Try to access the Yolink API to verify connection
    url = f"{base_url}/api"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    payload = {
        "method": "Home.getGeneralInfo",
        "time": int(time.time() * 1000)
    }

    try:
        print(f"Testing Yolink API Connection to URL: {url}")
        print(f"Request Headers: {headers}")
        print(f"Request Payload: {payload}")

        response = requests.post(url, headers=headers, json=payload)
        print(f"Yolink API Response Status Code: {response.status_code}")
        print(f"Yolink API Response: {response.text}")

        if response.status_code == 200:
            data = response.json()
            return jsonify({"status": "success", "data": data, "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to access Yolink API. Status code: {response.status_code}", "response": response.text})
    except Exception as e:
        print(f"Error connecting to Yolink API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})


@app.route('/get_devices', methods=['POST'])
def get_devices():
    home_id = request.json.get('home_id')
    config = load_config()
    token = config['yolink'].get('token')
    
    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    devices = yolink_api.get_device_list(home_id)
    return jsonify(devices)

@app.route('/save_mapping', methods=['POST'])
def save_mapping():
    data = request.json  # Expect a JSON payload of device-to-zone mappings
    with open(mapping_file, 'w') as file:
        yaml.dump(data, file)
    return jsonify({"status": "success", "message": "Mappings saved successfully"})

@app.route('/config', methods=['GET', 'POST'])
def config():
    if request.method == 'POST':
        data = request.json
        save_config(data)
        return jsonify({"status": "success", "message": "Configuration saved successfully"})
    else:
        config = load_config()
        return render_template('config.html', config=config)

# MQTT Configuration and Callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(userdata['topic'])  # Subscribe to the topic from the config
    else:
        print(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    print(f"Received message on topic {msg.topic}: {msg.payload}")
    
    # Load device mappings from file
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
            print(f"Triggering CHEKT for device {device_id} in zone {chekt_zone_id} with state {state}")
            # Add the logic to trigger CHEKT API
            trigger_chekt_event(chekt_zone_id, state)

    except Exception as e:
        print(f"Error processing message: {str(e)}")

def trigger_chekt_event(chekt_zone_id, event_state):
    """
    Trigger the CHEKT API based on the event state (e.g., door open or motion detected).
    """
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
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"CHEKT zone {chekt_zone_id} updated successfully")
        else:
            print(f"Failed to update CHEKT zone {chekt_zone_id}. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error communicating with CHEKT API: {str(e)}")

def run_mqtt_client():
    config = load_config()
    try:
        mqtt_client = mqtt.Client(userdata={"topic": config['mqtt']['topic']})
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.connect(config['mqtt']['url'], config['mqtt']['port'])
        mqtt_client.loop_forever()
    except socket.gaierror as e:
        print(f"MQTT connection failed: {str(e)}. Please check the MQTT broker address.")
    except Exception as e:
        print(f"Unexpected error with MQTT client: {str(e)}")

# Start the MQTT client in a separate thread
mqtt_thread = threading.Thread(target=run_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)