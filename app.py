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

mqtt_client_instance = None  # Global variable to store the MQTT client instance

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

def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as yaml_file:
            return yaml.safe_load(yaml_file)
    return {}

def save_to_yaml(file_path, data):
    with open(file_path, 'w') as yaml_file:
        yaml.dump(data, yaml_file)

def generate_yolink_token(uaid, secret_key):
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret_key}

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")

            if token:
                expiry_time = time.time() + expires_in - 60
                config_data['yolink']['token'] = token
                config_data['yolink']['token_expiry'] = expiry_time
                save_config(config_data)
                return token
        else:
            logger.error(f"Failed to generate Yolink token. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logger.error(f"Error generating Yolink token: {str(e)}")
    return None

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

def handle_token_expiry():
    if is_token_expired():
        return generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
    return config_data['yolink']['token']

class YoLinkAPI:
    def __init__(self, token):
        self.base_url = "https://api.yosmart.com/open/yolink/v2/api"
        self.token = token

    def get_device_list(self):
        url = self.base_url
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.token}"
        }
        data = {"method": "Home.getDeviceList", "time": int(time.time() * 1000)}
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
    try:
        new_mappings = request.get_json()
        if not new_mappings or 'mappings' not in new_mappings:
            return jsonify({"status": "error", "message": "Invalid mappings data."}), 400

        existing_mappings = load_yaml('mappings.yaml') or {'mappings': []}
        if 'mappings' in existing_mappings:
            existing_mappings['mappings'].extend(new_mappings['mappings'])
        else:
            existing_mappings['mappings'] = new_mappings['mappings']

        save_to_yaml("mappings.yaml", existing_mappings)
        return jsonify({"status": "success", "message": "Mapping saved successfully."})

    except Exception as e:
        logger.error(f"Error in save_mapping: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route('/refresh_yolink_devices', methods=['GET'])
def refresh_yolink_devices():
    token = handle_token_expiry()
    if not token:
        return jsonify({"status": "error", "message": "Failed to generate token."})

    yolink_api = YoLinkAPI(token)
    devices = yolink_api.get_device_list()
    if devices and devices.get("code") == "000000":
        save_to_yaml("devices.yaml", {"devices": devices["data"]["devices"]})
        restart_mqtt_client()
        return jsonify({"status": "success", "message": "Devices refreshed and MQTT restarted."})
    else:
        return jsonify({"status": "error", "message": "Failed to retrieve device list."})

def restart_mqtt_client():
    global mqtt_client_instance
    if mqtt_client_instance:
        mqtt_client_instance.disconnect()
        mqtt_client_instance.loop_stop()
    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()

@app.route('/')
def index():
    devices_data = load_yaml('devices.yaml')
    mappings_data = load_yaml('mappings.yaml')
    return render_template('index.html', devices=devices_data.get('devices', []), mappings=mappings_data)

def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get('deviceId')
        state = payload['data'].get('state', 'Unknown state')

        if device_id:
            mappings = load_yaml(config_data['files']['map_file']).get('mappings', [])
            mapping = next((m for m in mappings if m['yolink_device_id'].strip() == device_id), None)
            if mapping:
                chekt_zone = mapping.get('chekt_zone')
                device_type = parse_device_type(payload.get('event'), payload)
                if device_type and should_trigger_event(state, device_type):
                    chekt_event = map_state_to_event(state, device_type)
                    trigger_chekt_event(chekt_zone, chekt_event)
                else:
                    logger.info(f"State {state} for device {device_id} does not trigger an event. Skipping.")
            else:
                logger.warning(f"No mapping found for device {device_id}")
        else:
            logger.warning("Received message without device ID.")
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

def parse_device_type(event_type, payload):
    if "MotionSensor" in event_type:
        return 'motion'
    elif "DoorSensor" in event_type:
        return 'door_contact'
    elif "LeakSensor" in event_type:
        return 'leak_sensor'
    return None

def should_trigger_event(state, device_type):
    if device_type == 'door_contact' and state in ['open', 'closed']:
        return True
    elif device_type == 'motion' and state == 'alert':
        return True
    elif device_type == 'leak_sensor' and state == 'alert':
        return True
    return False

def map_state_to_event(state, device_type):
    if device_type == 'door_contact':
        return f"Door {state}"
    elif device_type == 'motion':
        return "Motion detected"
    elif device_type == 'leak_sensor':
        return "Water leak detected"
    return "Unknown Event"

def trigger_chekt_event(bridge_channel, event_description):
    chekt_api_url = f"http://{config_data['chekt']['ip']}:{config_data['chekt']['port']}/api/v1/channels/{bridge_channel}/events"
    chekt_payload = {"event_description": event_description}
    headers = {"Authorization": f"Bearer {config_data['chekt']['api_token']}", "Content-Type": "application/json"}
    try:
        response = requests.post(chekt_api_url, headers=headers, json=chekt_payload)
        if response.status_code == 200:
            logger.info(f"Successfully triggered event '{event_description}' on bridge channel {bridge_channel}")
        else:
            logger.error(f"Failed to trigger event on bridge channel {bridge_channel}. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logger.error(f"Error while triggering CHEKT event: {str(e)}")

def run_mqtt_client():
    token, client_id = force_generate_token_and_client()
    devices_data = load_yaml(config_data['files']['device_file'])
    home_id = devices_data.get('homes', {}).get('id')
    mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": f"yl-home/{home_id}/+/report"})
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.username_pw_set(username=token, password=None)
    mqtt_client.connect(config_data['mqtt']['url'].replace("mqtt://", ""), int(config_data['mqtt']['port']))
    mqtt_client.loop_forever()

mqtt_thread = threading.Thread(target=run_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
