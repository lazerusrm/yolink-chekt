import paho.mqtt.client as mqtt
import time
from config import load_config
from mappings import get_mapping
from monitor_mqtt import publish_update

client = None


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        config = load_config()
        home_id = config["home_id"]
        topic = config["mqtt"]["topic"].replace("${Home ID}", home_id)
        client.subscribe(topic)
        logger.info(f"Connected and subscribed to {topic}")
    else:
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
        # Simulate CHEKT alarm (replace with actual API call)
        chekt_config = config["chekt"]
        alarm_data = {
            "device_id": device_id,
            "zone": mapping.get("receiver_device_id", ""),
            "state": state
        }
        logger.info(f"Sending CHEKT alarm: {alarm_data}")
        # requests.post(f"http://{chekt_config['ip']}:{chekt_config['port']}/alarm", json=alarm_data, headers={"Authorization": f"Bearer {chekt_config['api_token']}"})

    save_device_data(device_id, device)
    publish_update(device_id, {"state": state, "alarms": device["alarms"]})


def on_disconnect(client, userdata, rc):
    if rc != 0:
        logger.warning("YoLink MQTT disconnected. Reconnecting...")
        time.sleep(5)
        run_mqtt_client()


def run_mqtt_client():
    global client
    config = load_config()
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.connect(config["mqtt"]["url"].replace("mqtt://", ""), config["mqtt"]["port"])
    client.loop_start()


if __name__ == "__main__":
    run_mqtt_client()