import paho.mqtt.client as mqtt
import json
import time
import logging
import secrets
from config import load_config
from db import redis_client
from device_manager import get_device_data, save_device_data, get_access_token
from mappings import get_mapping
from alerts import trigger_alert get_last_door_prop_alarm, set_last_door_prop_alarm
from monitor_mqtt import publish_update
import requests

# Logging Setup
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler("/app/logs/yolink.log", maxBytes=10*1024*1024, backupCount=5)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


client = None
connected = False


def should_trigger_event(current_state, previous_state, device_type=None):
    """
    Determine if an alert should be triggered based on state transitions or state="alert".
    """
    logger.debug(f"Checking trigger: current_state={current_state}, previous_state={previous_state}")

    # Trigger if state is "alert"
    if current_state == "alert":
        logger.info(f"Triggering alert: state is 'alert'")
        return True

    # Trigger if state transitions from "open" to "closed" or "closed" to "open"
    if previous_state and current_state:
        if (previous_state == "open" and current_state == "closed") or (
                previous_state == "closed" and current_state == "open"):
            logger.info(f"Triggering alert: state changed from '{previous_state}' to '{current_state}'")
            return True

    return False


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

        # Get existing device data to retrieve previous_state
        device = get_device_data(device_id) or {}
        if not device.get("deviceId"):
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
                "door_prop_alarm": False,
                "previous_state": "unknown"
            }

        logger.debug(f"MQTT payload for {device_id}: {json.dumps(payload, indent=2)}")
        logger.debug(f"Current device data before update: {json.dumps(device, indent=2)}")

        data = payload.get("data", {})
        previous_state = device.get("state", "unknown")  # Current state before update becomes previous_state
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
        logger.debug(f"Mapping for device {device_id}: {mapping}")
        receiver_type = config.get("receiver_type", "CHEKT").upper()
        logger.debug(f"Receiver type: {receiver_type}")
        logger.debug(
            f"Device type: {device.get('type', 'unknown')}, State: {device['state']}, Previous State: {previous_state}")

        # If this is a DoorSensor and door prop alarm is enabled, process it specially:
        if device.get("type", "").lower() == "doorsensor" and mapping.get("door_prop_alarm", False):
            # Check if we have a closed -> open transition OR if the payload includes alertType "openRemind"
            if ((previous_state == "closed" and device["state"] == "open") or (data.get("alertType") == "openRemind")):
                # Use the payload's stateChangedAt if available, otherwise use the payload's time
                current_time = data.get("stateChangedAt") or data.get("time") or int(time.time() * 1000)
                last_trigger = get_last_door_prop_alarm(device_id)
                if last_trigger is None or (int(current_time) - int(last_trigger)) >= 30000:
                    # Update the last trigger time
                    set_last_door_prop_alarm(device_id, current_time)
                    # Trigger the CHEKT event with the fixed description "Door opened"
                    logger.info(
                        f"Door prop alarm triggered for device {device_id} on zone {mapping.get('chekt_zone')} at {current_time}")
                    trigger_chekt_event(device_id, mapping.get("chekt_zone"))
                else:
                    wait_time = (30000 - (int(current_time) - int(last_trigger))) / 1000
                    logger.info(
                        f"Door prop alarm for device {device_id} not triggered; waiting for another {wait_time:.1f} seconds.")
            else:
                logger.debug(
                    f"Door prop alarm conditions not met for device {device_id} (prev: {previous_state}, current: {device['state']}, alertType: {data.get('alertType')}).")
        else:
            # Normal processing for non-door sensors (or door sensors without door prop alarm enabled)
            if mapping and should_trigger_event(device["state"], previous_state):
                if receiver_type == "CHEKT":
                    logger.info(
                        f"Triggering CHEKT alert for device {device_id} with state {device['state']} (from {previous_state})")
                    trigger_alert(device_id, device["state"], device.get("type", "unknown"))
                elif receiver_type == "SIA":
                    # SIA logic here if needed.
                    pass

        # Finally, publish an update for this device.
        publish_update(device_id, {
            "state": device["state"],
            "alarms": device.get("alarms", {})
        })

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in MQTT payload: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing message for device {device_id}: {str(e)}")


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
    logger.info(
        f"Attempting YoLink MQTT connection: url={mqtt_config['url']}, port={mqtt_config['port']}, token={'*' * len(token)}")
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