import paho.mqtt.client as mqtt
import time
from config import load_config

client = None

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to monitor MQTT")
    else:
        logger.error(f"Monitor MQTT connection failed: {rc}")

def on_disconnect(client, userdata, rc):
    if rc != 0:
        logger.warning("Monitor MQTT disconnected. Reconnecting...")
        time.sleep(5)
        run_monitor_mqtt()

def run_monitor_mqtt():
    global client
    config = load_config()
    mqtt_config = config["mqtt_monitor"]
    client = mqtt.Client(mqtt_config["client_id"])
    client.username_pw_set(mqtt_config["username"], mqtt_config["password"])
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.connect(mqtt_config["url"].replace("mqtt://", ""), mqtt_config["port"])
    client.loop_start()

def publish_update(device_id, data):
    global client
    if client and client.is_connected():
        topic = f"monitor/devices/{device_id}"
        client.publish(topic, json.dumps(data))
        logger.info(f"Published update to monitor: {data}")

if __name__ == "__main__":
    run_monitor_mqtt()