import paho.mqtt.client as mqtt
import json
import time
import logging
from config import load_config

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

client = None
connected = False

def on_connect(client, userdata, flags, rc):
    global connected
    if rc == 0:
        logger.info("Connected to monitor MQTT")
        connected = True
    else:
        logger.error(f"Monitor MQTT connection failed with code {rc}")
        connected = False
        if rc == 5:
            logger.error("Authentication failed. Check username/password in config.")

def on_disconnect(client, userdata, rc):
    global connected
    if rc != 0:
        connected = False
        logger.warning("Monitor MQTT disconnected. Reconnecting...")
        time.sleep(5)
        run_monitor_mqtt()

def run_monitor_mqtt():
    global client, connected
    config = load_config()
    mqtt_config = config["mqtt_monitor"]
    logger.info(f"Attempting Monitor MQTT connection with config: url={mqtt_config['url']}, username={mqtt_config['username']}, password={'*' * len(mqtt_config['password']) if mqtt_config['password'] else 'None'}")
    client = mqtt.Client(mqtt_config["client_id"])
    if mqtt_config["username"] and mqtt_config["password"]:
        client.username_pw_set(mqtt_config["username"], mqtt_config["password"])
    else:
        logger.warning("No username/password provided for Monitor MQTT. Connection may fail if required.")
    try:
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.connect(mqtt_config["url"].replace("mqtt://", ""), mqtt_config["port"])
        client.loop_start()
        connected = True
    except Exception as e:
        logger.error(f"Monitor MQTT initial connection failed: {e}")
        connected = False

def publish_update(device_id, data):
    global client, connected
    if client and connected:
        topic = f"monitor/devices/{device_id}"
        client.publish(topic, json.dumps(data))
        logger.info(f"Published update to monitor: {data}")

if __name__ == "__main__":
    run_monitor_mqtt()