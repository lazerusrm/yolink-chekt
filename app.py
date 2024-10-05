import yaml
import json
import requests
import hashlib
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

class YoLinkDevice:
    def __init__(self, url, csid, csseckey, serial_number, friendly_name="Unknown"):
        self.url = url
        self.csid = csid
        self.csseckey = csseckey
        self.serial_number = serial_number
        self.friendly_name = friendly_name
        self.device_data = {}

    def build_device_api_request_data(self):
        self.device_data = {
            "method": "Manage.addYoLinkDevice",
            "params": {"sn": self.serial_number},
        }

    def enable_device_api(self):
        headers = {
            'Content-Type': 'application/json',
            'YS-CSID': self.csid,
            'ys-sec': hashlib.md5((json.dumps(self.device_data) + self.csseckey).encode('utf-8')).hexdigest(),
        }
        try:
            response = requests.post(self.url, json=self.device_data, headers=headers)
            if response.status_code == 200:
                self.device_data = response.json().get('data', {})
                self.friendly_name = self.device_data.get('name', 'Unknown')
            else:
                print(f"Failed to enable device API for {self.serial_number}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error enabling device API for {self.serial_number}: {str(e)}")

    def get_friendly_name(self):
        return self.friendly_name

    def get_id(self):
        return self.device_data.get('deviceId', 'Unknown')

    def get_type(self):
        return self.device_data.get('type', 'Unknown')

# Query Yolink devices (from the local API)
def query_yolink_devices(url, csid, csseckey, device_list):
    devices = []
    for device_data in device_list:
        yolink_device = YoLinkDevice(url, csid, csseckey, device_data['serial_number'], "")
        yolink_device.build_device_api_request_data()
        yolink_device.enable_device_api()
        devices.append({
            'name': yolink_device.get_friendly_name(),
            'id': yolink_device.get_id(),
            'type': yolink_device.get_type()
        })
    return devices

@app.route('/')
def index():
    # Load device and mapping configurations
    config = load_config()
    devices = []
    mappings = {}

    if os.path.exists(device_file):
        with open(device_file, 'r') as df:
            devices = yaml.safe_load(df).get('device_parameters', [])

    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as mf:
            mappings = yaml.safe_load(mf)

    # Query Yolink devices
    yolink_devices = query_yolink_devices(config['yolink']['url'], config['yolink']['csid'], config['yolink']['csseckey'], devices)

    return render_template('index.html', devices=yolink_devices, mappings=mappings, config=config)

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
    url = f"https://external.chekt.click/api/v1/zones/{chekt_zone_id}/events"
    
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