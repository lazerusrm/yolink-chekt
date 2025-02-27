import paho.mqtt.client as mqtt
import json
import time
import logging
from config import load_config
from db import redis_client
from device_manager import get_device_data, save_device_data
from mappings import get_mapping
from monitor_mqtt import publish_update
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

client = None
connected = False

def on_connect(client, userdata, flags, rc):
    global connected
    if rc == 0:
        config = load_config()
        home_id = config["home_id"]
        topic = config["mqtt"]["topic"].replace("${Home ID}", home_id)
        client.subscribe(topic)
        connected = True
        logger.info(f"Connected and subscribed to {topic}")
    else:
        connected = False
        logger.error(f"YoLink MQTT connection failed with code {rc}")
        if rc == 5:
            logger.error("Authentication failed. Check YoLink MQTT credentials.")

def on_message(client, userdata, msg):
    payload = json.loads(msg.payload.decode())
    device_id = payload.get("deviceId")
    if not device_id:
        logger.warning("No deviceId in MQTT payload")
        return
    device = get_device_data(device_id)
    if not device:
        logger.warning(f"Device {device_id} not found in store, initializing")
        device = {
            "deviceId": device_id,
            "name": f"Device {device_id[-4:]}",
            "type": "unknown",
            "state": "unknown",
            "signal": "unknown",
            "battery": "unknown",
            "last_seen": "never",
            "alarms": {},
            "temperature": "unknown",
            "humidity": "unknown"
        }

    # Log the full payload for debugging
    logger.debug(f"MQTT payload for {device_id}: {json.dumps(payload, indent=2)}")

    # Update device data from payload
    data = payload.get("data", {})
    device["state"] = data.get("state", device.get("state", "unknown"))
    device["battery"] = data.get("battery", device.get("battery", "unknown"))
    device["signal"] = data.get("loraInfo", {}).get("signal", data.get("signal", device.get("signal", "unknown")))
    device["temperature"] = data.get("temperature", device.get("temperature", "unknown"))
    device["humidity"] = data.get("humidity", device.get("humidity", "unknown"))
    device["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if "alarm" in data:
        device["alarms"]["state"] = data["alarm"]

    # Handle nested state objects or other fields based on devices.yaml
    if isinstance(device["state"], dict):
        device["state"] = data.get("state", device["state"])
    if "type" in payload:
        device["type"] = payload["type"]

    config = load_config()
    mapping = get_mapping(device_id)
    if mapping and device["state"] == "open" and config["receiver_type"] == "CHEKT":
        chekt_config = config["chekt"]
        alarm_data = {
            "device_id": device_id,
            "zone": mapping.get("receiver_device_id", ""),
            "state": device["state"]
        }
        logger.info(f"Sending CHEKT alarm: {alarm_data}")
        try:
            requests.post(
                f"http://{chekt_config['ip']}:{chekt_config['port']}/alarm",
                json=alarm_data,
                headers={"Authorization": f"Bearer {chekt_config['api_token']}"},
                timeout=5
            )
        except requests.RequestException as e:
            logger.error(f"Failed to send CHEKT alarm: {e}")

    save_device_data(device_id, device)
    publish_update(device_id, {"state": device["state"], "alarms": device.get("alarms", {})})

def on_disconnect(client, userdata, rc):
    global connected
    if rc != 0:
        connected = False
        logger.warning(f"YoLink MQTT disconnected with code {rc}. Reconnecting...")
        time.sleep(5)
        run_mqtt_client()

def run_mqtt_client():
    global client, connected
    config = load_config()
    mqtt_config = config["mqtt"]
    token = config["yolink"]["token"]
    logger.info(
        f"Attempting YoLink MQTT connection: url={mqtt_config['url']}, port={mqtt_config['port']}, token={'*' * len(token) if token else 'None'}")
    client = mqtt.Client()
    client.username_pw_set(username=token, password=None)  # Use token as username
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    try:
        client.connect(mqtt_config["url"].replace("mqtt://", ""), mqtt_config["port"], keepalive=60)
        client.loop_start()
        connected = True
    except Exception as e:
        logger.error(f"YoLink MQTT initial connection failed: {e}")
        connected = False
        time.sleep(5)
        run_mqtt_client()

if __name__ == "__main__":
    run_mqtt_client()