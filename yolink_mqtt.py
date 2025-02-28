import paho.mqtt.client as mqtt
import json
import time
import logging
from config import load_config
from db import redis_client
from device_manager import get_device_data, save_device_data, get_access_token
from mappings import get_mapping
from monitor_mqtt import publish_update
import requests

# Configure logging to a file
logging.basicConfig(
    filename="yolink_mqtt.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

client = None
connected = False

def on_connect(client, userdata, flags, rc):
    global connected
    if rc == 0:
        config = load_config()
        topic = config["mqtt"]["topic"].replace("${Home ID}", config["home_id"])
        client.subscribe(topic)
        connected = True
        logger.info(f"Connected and subscribed to {topic}")
    else:
        connected = False
        logger.error(f"YoLink MQTT connection failed with code {rc}")
        if rc == 5:  # Authentication error, likely due to expired token
            logger.warning("Authentication failed, attempting to reconnect with fresh token...")
            time.sleep(5)
            run_mqtt_client()

def on_disconnect(client, userdata, rc):
    global connected
    if rc != 0:
        connected = False
        logger.warning(f"YoLink MQTT disconnected with code {rc}. Reconnecting...")
        time.sleep(5)
        run_mqtt_client()

def on_message(client, userdata, msg):
    logger.info(f"Received message on topic {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        device_id = payload.get("deviceId")
        if not device_id:
            logger.warning("No deviceId in MQTT payload")
            return

        device = get_device_data(device_id)
        if not device:
            logger.warning(f"Device {device_id} not found, initializing")
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
                "humidity": "unknown",
                "chekt_zone": "N/A",
                "door_prop_alarm": False
            }

        logger.debug(f"MQTT payload for {device_id}: {json.dumps(payload, indent=2)}")

        data = payload.get("data", {})
        if "state" in data:
            device["state"] = data["state"]
        if "battery" in data:
            device["battery"] = data["battery"]
        if "signal" in data:
            device["signal"] = data["signal"]
        elif "loraInfo" in data and "signal" in data["loraInfo"]:
            device["signal"] = data["loraInfo"]["signal"]
        if "temperature" in data:
            device["temperature"] = data["temperature"]
        if "humidity" in data:
            device["humidity"] = data["humidity"]
        if "alarm" in data:
            device["alarms"]["state"] = data["alarm"]
        if "type" in payload:
            device["type"] = payload["type"]
        device["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")

        save_device_data(device_id, device)

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

        publish_update(device_id, {"state": device["state"], "alarms": device.get("alarms", {})})
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")

def run_mqtt_client():
    global client, connected
    config = load_config()
    token = get_access_token(config)  # Ensure a valid token on startup
    if not token:
        logger.error("Failed to obtain a valid YoLink token. Retrying in 5 seconds...")
        time.sleep(5)
        run_mqtt_client()
        return

    mqtt_config = config["mqtt"]
    logger.info(f"Attempting YoLink MQTT connection: url={mqtt_config['url']}, port={mqtt_config['port']}, token={'*' * len(token)}")
    client = mqtt.Client()
    client.username_pw_set(username=token, password=None)
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