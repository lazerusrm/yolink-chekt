import yaml
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import threading
import paho.mqtt.client as mqtt
import os
import socket
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

# Load configuration from file or memory
config_file = "config.yaml"
config_data = defaultdict(lambda: None)

# Utility Functions
def load_config():
    global config_data
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data.update(yaml.safe_load(file))
    return config_data

def save_config(data):
    with open(config_file, 'w') as file:
        yaml.dump(data, file)

def get_headers(token):
    return {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }

def make_api_request(url, headers, data=None, method="POST"):
    try:
        response = requests.post(url, headers=headers, json=data) if method == "POST" else requests.get(url, headers=headers)
        return response
    except Exception as e:
        print(f"Error in request: {str(e)}")
        return None

def generate_yolink_token():
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        "grant_type": "client_credentials",
        "client_id": config_data['yolink']['uaid'],
        "client_secret": config_data['yolink']['secret_key']
    }
    response = make_api_request(url, headers, data)
    if response and response.status_code == 200:
        token = response.json().get("access_token")
        if token:
            config_data['yolink']['token'] = token
            save_config(config_data)
            return token
    print(f"Failed to generate Yolink token. Status code: {response.status_code if response else 'N/A'}")
    return None

# Yolink API Class
class YoLinkAPI:
    def __init__(self):
        self.base_url = config_data['yolink']['base_url']
        self.token = config_data['yolink'].get('token') or generate_yolink_token()

    def get_homes(self):
        headers = get_headers(self.token)
        data = {"method": "Home.getGeneralInfo", "time": int(time.time() * 1000)}
        response = make_api_request(f"{self.base_url}/open/yolink/v2/api", headers, data)
        if response and response.status_code == 200:
            return response.json().get('data', {}).get('homes', [])
        elif response and response.status_code == 401:
            print("Token expired, generating a new one.")
            self.token = generate_yolink_token()
            return self.get_homes()  # Retry with new token
        return []

    def get_device_list(self, home_id):
        headers = get_headers(self.token)
        data = {"method": "Home.getDeviceList", "time": int(time.time() * 1000), "homeId": home_id}
        response = make_api_request(f"{self.base_url}/open/yolink/v2/api", headers, data)
        if response and response.status_code == 200:
            return response.json().get('data', {}).get('devices', [])
        elif response and response.status_code == 401:
            print("Token expired, generating a new one.")
            self.token = generate_yolink_token()
            return self.get_device_list(home_id)  # Retry with new token
        return []

# Flask Routes
@app.route('/')
def index():
    config = load_config()
    yolink_api = YoLinkAPI()
    homes = yolink_api.get_homes()
    mappings = yaml.safe_load(open(mapping_file)) if os.path.exists(mapping_file) else {}
    return render_template('index.html', homes=homes, mappings=mappings, config=config)

@app.route('/test_api/<service>', methods=['GET'])
def test_api(service):
    config = load_config()
    if service == 'yolink':
        yolink_api = YoLinkAPI()
        homes = yolink_api.get_homes()
        return jsonify({"status": "success" if homes else "error", "data": homes})
    elif service == 'chekt':
        url = f"http://{config['chekt']['ip']}:{config['chekt']['port']}/api/v1/"
        headers = get_headers(config['chekt']['api_token'])
        response = make_api_request(url, headers, method="GET")
        return jsonify({"status": "success" if response and response.status_code == 200 else "error", "response": response.text if response else "No response"})
    return jsonify({"status": "error", "message": "Unknown service"})

@app.route('/get_devices', methods=['POST'])
def get_devices():
    home_id = request.json.get('home_id')
    yolink_api = YoLinkAPI()
    devices = yolink_api.get_device_list(home_id)
    return jsonify(devices)

@app.route('/save_mapping', methods=['POST'])
def save_mapping():
    yaml.dump(request.json, open(mapping_file, 'w'))
    return jsonify({"status": "success", "message": "Mappings saved successfully"})

@app.route('/config', methods=['GET', 'POST'])
def config():
    if request.method == 'POST':
        save_config(request.json)
        return jsonify({"status": "success", "message": "Configuration saved successfully"})
    return render_template('config.html', config=load_config())

# MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    print("Connected" if rc == 0 else f"Failed to connect, return code {rc}")
    if rc == 0:
        client.subscribe(userdata['topic'])

def on_message(client, userdata, msg):
    print(f"Received message on topic {msg.topic}: {msg.payload}")
    mappings = yaml.safe_load(open(mapping_file)) if os.path.exists(mapping_file) else {}
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload['deviceId']
        state = payload['data']['state']
        if device_id in mappings:
            trigger_chekt_event(mappings[device_id], state)
    except Exception as e:
        print(f"Error processing message: {str(e)}")

def trigger_chekt_event(chekt_zone_id, event_state):
    url = f"http://{config_data['chekt']['ip']}:{config_data['chekt']['port']}/api/v1/zones/{chekt_zone_id}/events"
    headers = get_headers(config_data['chekt']['api_token'])
    data = {"event": event_state, "timestamp": int(time.time())}
    response = make_api_request(url, headers, data)
    if response and response.status_code in [200, 202]:
        print(f"CHEKT zone {chekt_zone_id} updated successfully")
    else:
        print(f"Failed to update CHEKT zone {chekt_zone_id}. Status code: {response.status_code if response else 'N/A'}")

# MQTT Thread
mqtt_thread = threading.Thread(target=lambda: mqtt.Client(userdata={"topic": config_data['mqtt']['topic']}).apply(lambda client: [setattr(client, k, v) for k, v in {"on_connect": on_connect, "on_message": on_message}.items()]) or client.connect(config_data['mqtt']['url'], int(config_data['mqtt']['port'])).loop_forever())
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)