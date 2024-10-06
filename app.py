import yaml
import json
import requests
import time
from flask import Flask, render_template, request, jsonify, Response
import threading
import paho.mqtt.client as mqtt
import os
import socket
from datetime import datetime

app = Flask(__name__)

# Load configuration from file or memory
config_file = "config.yaml"

config_data = {}

# Load configuration
def load_config():
    global config_data
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file)
    # Set default values if not provided
    config_data.setdefault('files', {})
    config_data['files'].setdefault('map_file', 'mappings.yaml')
    config_data['files'].setdefault('device_file', 'devices.yaml')
    return config_data

# Save configuration
def save_config(data):
    global config_data
    config_data = data
    with open(config_file, 'w') as file:
        yaml.dump(data, file)

# Generate Yolink token
def generate_yolink_token(uaid, secret_key):
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
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
                add_to_log("Failed to obtain token, check UAID and Secret Key.")
        else:
            add_to_log(f"Failed to generate Yolink token. Status code: {response.status_code}")
            add_to_log(f"Response: {response.text}")
    except Exception as e:
        add_to_log(f"Error generating Yolink token: {str(e)}")
    return None

# Yolink API class
class YoLinkAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip('/')  # Ensure no trailing slash
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

        add_to_log(f"Sending request to Yolink API: {url}")
        add_to_log(f"Request Headers: {json.dumps(headers, indent=2)}")
        add_to_log(f"Request Payload: {json.dumps(data, indent=2)}")
        
        try:
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response Code: {response.status_code}")
            add_to_log(f"Response Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('homes', [])
            elif response.status_code == 401 and "expired" in response.text.lower():
                add_to_log("Token expired, generating a new one.")
                self.token = generate_yolink_token(config_data['yolink'].get('uaid', ''), config_data['yolink'].get('secret_key', ''))
                return self.get_homes()
            else:
                add_to_log(f"Failed request. Status code: {response.status_code} - {response.text}")
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

        try:
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response Code: {response.status_code}")
            add_to_log(f"Response Body: {response.text}")
            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            else:
                add_to_log(f"Failed to get device list. Status code: {response.status_code}")
                add_to_log(f"Response: {response.text}")
        except Exception as e:
            add_to_log(f"Error getting device list: {str(e)}")
        return []

logs = []

# Add message to log
def add_to_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp}: {message}"
    print(log_entry)
    logs.append(log_entry)

# Get logs endpoint
@app.route('/get_logs', methods=['GET'])
def get_logs():
    return Response("\n".join(logs), mimetype='text/plain')

# Index route
@app.route('/')
def index():
    config = load_config()
    mappings = {}

    if os.path.exists(config['files']['map_file']):
        with open(config['files']['map_file'], 'r') as mf:
            mappings = yaml.safe_load(mf)

    token = config['yolink'].get('token')
    if not token:
        token = generate_yolink_token(config['yolink'].get('uaid', ''), config['yolink'].get('secret_key', ''))

    if 'base_url' not in config['yolink']:
        add_to_log("Configuration Error: 'base_url' key is missing in Yolink configuration.")
        return render_template('index.html', devices=[], mappings=mappings, config=config, error="Configuration Error: 'base_url' key is missing in Yolink configuration.")

    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    homes = yolink_api.get_homes()

    return render_template('index.html', homes=homes, mappings=mappings, config=config)

# Additional endpoints for testing APIs, saving mappings, etc.

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)