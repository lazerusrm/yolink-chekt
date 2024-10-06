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
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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

    logging.debug(f"Sending token request to URL: {url}")
    try:
        response = requests.post(url, headers=headers, data=data)
        logging.debug(f"Token response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                config_data['yolink']['token'] = token
                save_config(config_data)
                return token
            else:
                logging.error("Failed to obtain Yolink token. Check UAID and Secret Key.")
        else:
            logging.error(f"Failed to generate Yolink token. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error generating Yolink token: {str(e)}")

    return None

class YoLinkAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def request_with_token_refresh(self, data):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=data)
            logging.debug(f"Response Code: {response.status_code}")
            logging.debug(f"Response Body: {response.text}")

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401 and "token is expired" in response.text.lower():
                # Token expired, regenerate and retry
                logging.warning("Token expired, regenerating...")
                self.token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
                if self.token:
                    headers['Authorization'] = f"Bearer {self.token}"
                    response = requests.post(self.base_url, headers=headers, json=data)
                    if response.status_code == 200:
                        return response.json()
            else:
                logging.error(f"Failed request. Status code: {response.status_code} - {response.text}")

        except Exception as e:
            logging.error(f"Error during API request: {str(e)}")

        return None

    def get_homes(self):
        data = {
            "method": "Home.getGeneralInfo",
            "time": int(time.time() * 1000)
        }
        logging.debug(f"Sending get_homes request: {data}")
        return self.request_with_token_refresh(data).get('data', {}).get('homes', []) if self.request_with_token_refresh(data) else []

    def get_device_list(self, home_id):
        data = {
            "method": "Home.getDeviceList",
            "time": int(time.time() * 1000),
            "homeId": home_id
        }
        logging.debug(f"Sending get_device_list request: {data}")
        return self.request_with_token_refresh(data).get('data', {}).get('devices', []) if self.request_with_token_refresh(data) else []

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
        token = generate_yolink_token(config['yolink']['uaid'], config['yolink']['secret_key'])

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
    url = f"http://{chekt_ip}:{chekt_port}/api/v1/"
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json'
    }

    try:
        logging.debug(f"Testing CHEKT API Connection to URL: {url}")
        response = requests.get(url, headers=headers)
        logging.debug(f"CHEKT API Response Status Code: {response.status_code} - Response: {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}", "response": response.text})
    except Exception as e:
        logging.error(f"Error connecting to CHEKT API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/test_yolink_api', methods=['GET'])
def test_yolink_api():
    # Load configuration to get token
    config = load_config()
    token = config['yolink'].get('token')

    if not token:
        return jsonify({"status": "error", "message": "No token available. Please generate a token first."})

    base_url = config['yolink']['base_url']
    if not base_url:
        return jsonify({"status": "error", "message": "'base_url' key is missing in Yolink configuration."})

    # Try to access the Yolink API to verify connection
    yolink_api = YoLinkAPI(base_url, token)
    homes = yolink_api.get_homes()
    if homes:
        return jsonify({"status": "success", "data": homes})
    else:
        return jsonify({"status": "error", "message": "Failed to access Yolink API or no homes found."})

# Remaining route definitions (get_devices, save_mapping, etc.) can follow similar improvements...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
