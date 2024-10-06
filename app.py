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
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Load configuration from file or memory
config_file = "config.yaml"

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
    
    logger.debug(f"Sending token request to URL: {url}")
    try:
        response = requests.post(url, headers=headers, data=data)
        logger.debug(f"Token response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                logger.info("Successfully obtained Yolink token.")
                # Update token in the configuration and save it
                config_data['yolink']['token'] = token
                save_config(config_data)
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
        return token
    else:
        logger.error("Failed to generate a new Yolink token.")
        return None

class YoLinkAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def get_homes(self):
        url = f"{self.base_url}open/yolink/v2/api"
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
                return response.json().get('data', {}).get('homes', [])
            elif response.status_code == 401:
                logger.warning("Unauthorized request. Token may be invalid or expired.")
                self.token = handle_token_expiry()
                return self.get_homes()  # Retry after getting a new token
            else:
                logger.error(f"Failed to retrieve homes. Status code: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error retrieving homes: {str(e)}")

        return []

    def get_device_list(self, home_id):
        url = f"{self.base_url}open/yolink/v2/api"
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

@app.route('/')
def index():
    # Load device and mapping configurations
    config = load_config()
    mappings = {}

    if os.path.exists(config['files']['map_file']):
        with open(config['files']['map_file'], 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Generate Yolink token if it doesn't exist
    token = config['yolink'].get('token')
    if not token:
        token = generate_yolink_token(config['yolink'].get('uaid'), config['yolink'].get('secret_key'))
    
    # Check if required keys are available
    if 'base_url' not in config['yolink']:
        return render_template('index.html', devices=[], mappings=mappings, config=config, error="Configuration Error: 'base_url' key is missing in Yolink configuration.")

    # Query Yolink homes
    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    homes = yolink_api.get_homes()

    return render_template('index.html', homes=homes, mappings=mappings, config=config)

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """
    Fetch logs for displaying on the web interface.
    """
    try:
        with open('application.log', 'r') as log_file:
            logs = log_file.read()
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found."})

# Other functions like test_chekt_api, save_mapping, and MQTT methods would also follow the same detailed logging structure for debugging.

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
