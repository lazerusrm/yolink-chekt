import paho.mqtt.client as mqtt
import threading
import time
import json
import logging
import requests
import uuid
from config import load_config, save_config, config_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

open_doors = {}  # {device_id: open_time}
device_data = {}  # {device_id: {state, type, last_updated, door_prop_alarm}}

def is_token_expired() -> bool:
    """Check if the current token is expired."""
    yolink_data = config_data.get("yolink", {})
    expiry_time = yolink_data.get("token_expiry", 0)
    current_time = time.time()
    return current_time >= expiry_time

def generate_yolink_token(uaid: str, secret_key: str) -> str | None:
    """Generate a new YoLink token using UAID and Secret Key."""
    url = "https://api.yosmart.com/open/yolink/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret_key}
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")
            if token:
                expiry_time = time.time() + expires_in - 60  # Early refresh
                config_data["yolink"]["token"] = token
                config_data["yolink"]["token_expiry"] = expiry_time
                save_config()
                logger.info("YoLink token generated successfully")
                return token
            else:
                logger.error("Failed to obtain YoLink token. Check UAID and Secret Key.")
        else:
            logger.error(f"Token generation failed: {response.status_code}, {response.text}")
    except requests.RequestException as e:
        logger.error(f"Error generating YoLink token: {e}")
    return None

def verify_yolink_token() -> bool:
    """Verify token validity, refreshing if expired."""
    if is_token_expired():
        uaid = config_data["yolink"]["uaid"]
        secret_key = config_data["yolink"]["secret_key"]
        if not uaid or not secret_key:
            logger.error("UAID or Secret Key missing from config.")
            return False
        return generate_yolink_token(uaid, secret_key) is not None
    return True

def token_refresh_thread() -> None:
    """Proactively refresh token in the background."""
    while True:
        if is_token_expired():
            verify_yolink_token()
        time.sleep(60)

def parse_device_type(event_type: str, payload: dict) -> str | None:
    """Determine device type from event."""
    event_lower = event_type.lower()
    if "doorsensor" in event_lower:
        return "door"
    elif "motionsensor" in event_lower:
        return "motion"
    elif "leak" in event_lower:
        return "leak"
    return None

def update_device_data(device_id: str, payload: dict, device_type: str | None) -> None:
    """Update device state in memory with door prop alarm setting."""
    if device_type:
        existing_data = device_data.get(device_id, {})
        device_data[device_id] = {
            "state": payload["data"].get("state"),
            "type": device_type,
            "last_updated": time.time(),
            "door_prop_alarm": existing_data.get("door_prop_alarm", False) if device_type == "door" else False
        }

def trigger_alert(device_id: str, state: str, device_type: str) -> None:
    """Log an alert for a device condition."""
    logger.info(f"ALERT: {device_type} {device_id} is {state}")

def check_door_open_timeout() -> None:
    """Monitor doors for open-too-long conditions based on per-sensor settings."""
    while True:
        current_time = time.time()
        timeout = config_data.get("door_open_timeout", 30)
        for device_id, open_time in list(open_doors.items()):
            device = device_data.get(device_id, {})
            if (device.get("type") == "door" and
                device.get("state") == "open" and
                device.get("door_prop_alarm", False) and
                current_time - open_time > timeout):
                trigger_alert(device_id, "open too long", "door")
                del open_doors[device_id]
        time.sleep(1)

def on_connect(client: mqtt.Client, userdata, flags, rc: int) -> None:
    """Handle MQTT connection."""
    if rc == 0:
        topic = config_data["mqtt"]["topic"].replace("${Home ID}", config_data.get("home_id", "UNKNOWN_HOME_ID"))
        client.subscribe(topic)
        logger.info(f"Connected to MQTT broker and subscribed to {topic}")
    else:
        logger.error(f"Connection failed with code {rc}")

def on_message(client: mqtt.Client, userdata, msg: mqtt.MQTTMessage) -> None:
    """Process incoming MQTT messages."""
    try:
        payload = json.loads(msg.payload.decode())
        device_id = payload.get("deviceId")
        if device_id:
            event = payload.get("event", "").lower()
            device_type = parse_device_type(event, payload)
            update_device_data(device_id, payload, device_type)
            if device_type == "door":
                state = payload["data"].get("state")
                if state == "open":
                    open_doors[device_id] = time.time()
                elif state == "closed" and device_id in open_doors:
                    del open_doors[device_id]
    except Exception as e:
        logger.error(f"Message processing failed: {e}")

def run_mqtt_client():
    global mqtt_client_instance, mqtt_thread_running
    if mqtt_thread_running:
        logger.info("MQTT client already running")
        return

    load_config()  # Ensure latest config
    token = config_data['yolink'].get('token')
    if not token or is_token_expired():
        token = generate_yolink_token(config_data['yolink']['uaid'], config_data['yolink']['secret_key'])
        if not token:
            logger.error("Failed to obtain a valid YoLink token")
            return

    devices_data = load_yaml('devices.yaml') or {}
    home_id = devices_data.get('homes', {}).get('id', config_data.get('home_id', 'UNKNOWN_HOME_ID'))
    if home_id == 'UNKNOWN_HOME_ID':
        logger.warning("No valid home_id found in devices.yaml or config.yaml; using UNKNOWN_HOME_ID")

    mqtt_broker_url = config_data['mqtt']['url'].replace("mqtt://", "")
    mqtt_broker_port = config_data['mqtt']['port']
    mqtt_topic = config_data['mqtt']['topic'].replace("${Home ID}", home_id)
    client_id = str(uuid.uuid4())

    mqtt_client = mqtt.Client(client_id=client_id, userdata={"topic": mqtt_topic})
    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect
    mqtt_client.on_message = on_message
    mqtt_client.username_pw_set(username=token, password=None)

    try:
        logger.info(f"Connecting to MQTT broker at {mqtt_broker_url}:{mqtt_broker_port} with topic {mqtt_topic}")
        mqtt_client.connect(mqtt_broker_url, mqtt_broker_port)
        mqtt_client_instance = mqtt_client
        mqtt_thread_running = True
        mqtt_client.loop_forever()
    except Exception as e:
        logger.error(f"MQTT client error: {e}")
        mqtt_thread_running = False

if __name__ == "__main__":
    run_mqtt_client()