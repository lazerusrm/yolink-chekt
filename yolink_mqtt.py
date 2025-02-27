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
connected = False  # Global status variable


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
        logger.error(f"YoLink MQTT connection failed: {rc}")


def on_message(client, userdata, msg):
    payload = json.loads(msg.payload.decode())
    device_id = payload.get("deviceId")
    if not device_id:
        return
    device = get_device_data(device_id)
    if not device:
        logger.warning(f"Device {device_id} not found")
        return

    # Update device state
    state = payload["data"].get("state", device.get("state", "unknown"))
    device["state"] = state
    device["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if "alarm" in payload["data"]:
        device["alarms"]["state"] = payload["data"]["alarm"]

    # Check for alarms
    config = load_config()
    mapping = get_mapping(device_id)
    if mapping and state == "open" and config["receiver_type"] == "CHEKT":
        chekt_config = config["chekt"]
        alarm_data = {
            "device_id": device_id,
            "zone": mapping.get("receiver_device_id", ""),
            "state": state
        }
        logger.info(f"Sending CHEKT alarm: {alarm_data}")
        requests.post(
            f"http://{chekt_config['ip']}:{chekt_config['port']}/alarm",
            json=alarm_data,
            headers={"Authorization": f"Bearer {chekt_config['api_token']}"}
        )

    save_device_data(device_id, device)
    publish_update(device_id, {"state": state, "alarms": device.get("alarms", {})})


def on_disconnect(client, userdata, rc):
    global connected
    if rc != 0:
        connected = False
        logger.warning("YoLink MQTT disconnected. Reconnecting...")
        time.sleep(5)
        run_mqtt_client()


def run_mqtt_client():
    global client, connected
    config = load_config()
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.connect(config["mqtt"]["url"].replace("mqtt://", ""), config["mqtt"]["port"])
    client.loop_start()
    connected = True  # Assume initial connection attempt succeeds


if __name__ == "__main__":
    run_mqtt_client()