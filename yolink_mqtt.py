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

def run_mqtt_client() -> None:
    """Run the MQTT client with token handling."""
    load_config()
    if not verify_yolink_token():
        logger.error("Initial token generation failed. Exiting.")
        return

    mqtt_config = config_data["mqtt"]
    client_id = str(uuid.uuid4())
    client = mqtt.Client(client_id=client_id)
    client.on_connect = on_connect
    client.on_message = on_message

    # Use token as username if no specific credentials provided
    username = mqtt_config.get("username") or config_data["yolink"]["token"]
    password = mqtt_config.get("password")
    if username:
        client.username_pw_set(username, password)

    threading.Thread(target=token_refresh_thread, daemon=True).start()
    threading.Thread(target=check_door_open_timeout, daemon=True).start()

    retry_delay = 5
    while True:
        try:
            client.connect(mqtt_config["url"].replace("mqtt://", ""), mqtt_config["port"])
            client.loop_forever()
        except Exception as e:
            logger.error(f"MQTT connection failed: {e}. Retrying in {retry_delay}s")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

if __name__ == "__main__":
    run_mqtt_client()