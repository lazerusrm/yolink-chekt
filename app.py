import yaml
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import threading
import paho.mqtt.client as mqtt
import os
import socket
from datetime import datetime

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

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

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

    log_message("Attempting to generate Yolink token...")
    
    try:
        response = requests.post(url, headers=headers, data=data)
        log_message(f"Yolink Token Generation Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                config_data['yolink']['token'] = token
                save_config(config_data)
                log_message("Successfully obtained Yolink token.")
                return token
            else:
                log_message("Failed to obtain token, check UAID and Secret Key.")
                return None
        else:
            log_message(f"Failed to generate Yolink token. Status code: {response.status_code}")
            return None
    except Exception as e:
        log_message(f"Error generating Yolink token: {str(e)}")
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

        log_message(f"Sending get_homes request to URL: {url}")
        log_message(f"Request Headers: {json.dumps(headers, indent=2)}")
        log_message(f"Request Payload: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(url, json=data, headers=headers)
            log_message(f"Response Code: {response.status_code}")
            log_message(f"Response Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('homes', [])
            elif response.status_code == 401 and "token is expired" in response.text.lower():
                log_message("Token is expired. Generating a new token...")
                new_token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
                if new_token:
                    self.token = new_token
                    headers['Authorization'] = f"Bearer {new_token}"
                    response = requests.post(url, json=data, headers=headers)
                    log_message(f"Retry Response Code: {response.status_code}")
                    log_message(f"Retry Response Body: {response.text}")
                    if response.status_code == 200:
                        return response.json().get('data', {}).get('homes', [])
            else:
                log_message(f"Failed to get home info. Status code: {response.status_code}")
                return []
        except Exception as e:
            log_message(f"Error getting home info: {str(e)}")
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

        log_message(f"Sending get_device_list request to URL: {url}")
        log_message(f"Request Headers: {json.dumps(headers, indent=2)}")
        log_message(f"Request Payload: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(url, json=data, headers=headers)
            log_message(f"Response Code: {response.status_code}")
            log_message(f"Response Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            else:
                log_message(f"Failed to get device list. Status code: {response.status_code}")
                return []
        except Exception as e:
            log_message(f"Error getting device list: {str(e)}")
            return []

@app.route('/')
def index():
    # Load device and mapping configurations
    config = load_config()
    mappings = {}

    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Generate Yolink token if it doesn't exist or is invalid
    token = config['yolink'].get('token')
    if not token:
        log_message("No token found, generating a new token...")
        token = generate_yolink_token(config['yolink'].get('uaid', ''), config['yolink'].get('secret_key', ''))

    # Check if required keys are available
    if 'base_url' not in config['yolink']:
        log_message("Configuration Error: 'base_url' key is missing in Yolink configuration.")
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
        log_message("CHEKT API configuration (IP or port) is missing.")
        return jsonify({"status": "error", "message": "CHEKT API configuration (IP or port) is missing."})

    # Try to access the CHEKT API health endpoint to verify the connection
    url = f"http://{chekt_ip}:{chekt_port}/api/v1/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json'
    }

    log_message(f"Testing CHEKT API Connection to URL: {url}")
    log_message(f"Request Headers: {json.dumps(headers, indent=2)}")

    try:
        response = requests.get(url, headers=headers)
        log_message(f"CHEKT API Response Status Code: {response.status_code}")
        log_message(f"CHEKT API Response: {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}", "response": response.text})
    except Exception as e:
        log_message(f"Error connecting to CHEKT API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
