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

def generate_yolink_token():
    """
    Generate the Yolink access token using the UAID and Secret Key.
    """
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        "grant_type": "client_credentials",
        "client_id": config_data['yolink']['uaid'],
        "client_secret": config_data['yolink']['secret_key']
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                config_data['yolink']['token'] = token
                save_config(config_data)
                add_to_log(f"Successfully obtained new Yolink token.")
                return token
            else:
                add_to_log("Failed to obtain Yolink token. Check UAID and Secret Key.")
        else:
            add_to_log(f"Failed to generate Yolink token. Status code: {response.status_code}\nResponse: {response.text}")
    except Exception as e:
        add_to_log(f"Error generating Yolink token: {str(e)}")
    return None

class YoLinkAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def get_homes(self):
        url = f"{self.base_url}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {
            "method": "Home.getGeneralInfo",
            "time": int(time.time() * 1000),
        }

        try:
            add_to_log(f"Sending request to Yolink API: {url}\nRequest Headers: {json.dumps(headers)}\nRequest Payload: {json.dumps(data)}")
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response Code: {response.status_code}\nResponse Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('homes', [])
            elif response.status_code == 401 or response.json().get("code") == "010104":
                # Token is expired, regenerate token and retry
                add_to_log("Token expired. Generating a new token...")
                self.token = generate_yolink_token()
                headers['Authorization'] = f"Bearer {self.token}"
                response = requests.post(url, json=data, headers=headers)
                if response.status_code == 200:
                    return response.json().get('data', {}).get('homes', [])
            else:
                add_to_log(f"Failed to get home info. Status code: {response.status_code}\nResponse: {response.text}")
        except Exception as e:
            add_to_log(f"Error getting home info: {str(e)}")
        return []

    def get_device_list(self, home_id):
        url = f"{self.base_url}"
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
            add_to_log(f"Sending request to Yolink API: {url}\nRequest Headers: {json.dumps(headers)}\nRequest Payload: {json.dumps(data)}")
            response = requests.post(url, json=data, headers=headers)
            add_to_log(f"Response Code: {response.status_code}\nResponse Body: {response.text}")

            if response.status_code == 200:
                return response.json().get('data', {}).get('devices', [])
            else:
                add_to_log(f"Failed to get device list. Status code: {response.status_code}\nResponse: {response.text}")
        except Exception as e:
            add_to_log(f"Error getting device list: {str(e)}")
        return []

def add_to_log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{timestamp}: {message}")

@app.route('/')
def index():
    config = load_config()
    mappings = {}

    if os.path.exists(config_data['files']['map_file']):
        with open(config_data['files']['map_file'], 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Generate Yolink token if it doesn't exist
    token = config['yolink'].get('token')
    if not token:
        token = generate_yolink_token()

    yolink_api = YoLinkAPI(config['yolink']['base_url'], token)
    homes = yolink_api.get_homes()

    return render_template('index.html', homes=homes, mappings=mappings, config=config)

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
        'Content-Type': 'application/json'
    }
    auth = ("apikey", api_token)

    try:
        add_to_log(f"Testing CHEKT API Connection to URL: {url}")
        response = requests.get(url, headers=headers, auth=auth)
        add_to_log(f"CHEKT API Response Status Code: {response.status_code}\nResponse: {response.text}")

        if response.status_code == 200:
            return jsonify({"status": "success", "message": "CHEKT API connection successful.", "debug_info": response.text})
        else:
            return jsonify({"status": "error", "message": f"Failed to connect to CHEKT API. Status code: {response.status_code}", "response": response.text})
    except Exception as e:
        add_to_log(f"Error connecting to CHEKT API: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

# Keep other necessary routes and functionality as you need

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
