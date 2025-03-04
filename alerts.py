import logging
import requests
import base64
from mappings import get_mapping
from db import redis_client

logger = logging.getLogger(__name__)

# Optionally, enable HTTP connection debugging (uncomment if needed)
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1
# logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
# logging.getLogger("requests.packages.urllib3").propagate = True

def map_state_to_event(state, device_type):
    if device_type == 'door_contact':
        if state == 'open':
            return "Door Opened"
        elif state == 'closed':
            return "Door Closed"
    elif device_type == 'motion':
        if state == 'alert':
            return "Motion Detected"
    elif device_type == 'leak_sensor':
        if state == 'alert':
            return "Water Leak Detected"
    return "Unknown Event"

def get_last_door_prop_alarm(device_id):
    """Retrieve the last door prop alarm trigger time (in ms) for a given device from Redis."""
    key = f"door_prop_alarm:{device_id}"
    ts = redis_client.get(key)
    return int(ts) if ts else None

def set_last_door_prop_alarm(device_id, timestamp):
    """Set the door prop alarm trigger time (in ms) for a given device in Redis."""
    key = f"door_prop_alarm:{device_id}"
    redis_client.set(key, str(timestamp))

def trigger_alert(device_id, state, device_type):
    from config import load_config
    config = load_config()
    receiver_type = config.get("receiver_type", "CHEKT").upper()
    if receiver_type not in ["CHEKT", "SIA"]:
        logger.error(f"Invalid receiver type: {receiver_type}. Defaulting to CHEKT.")
        receiver_type = "CHEKT"

    mapping = get_mapping(device_id)
    if not mapping:
        logger.warning(f"No mapping for device {device_id}")
        return

    event_description = map_state_to_event(state, device_type)
    logger.debug(f"Device {device_id} event description: {event_description}")

    if receiver_type == "CHEKT":
        chekt_zone = mapping.get('chekt_zone', 'N/A')
        if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
            logger.info(f"Triggering CHEKT event in zone {chekt_zone} for device {device_id}")
            trigger_chekt_event(device_id, chekt_zone)
        else:
            logger.warning(f"No valid CHEKT zone for device {device_id}. Mapping: {mapping}")
    elif receiver_type == "SIA":
        sia_zone = mapping.get('sia_zone', 'N/A')
        sia_config = config.get('sia', {})
        if sia_zone and sia_zone.strip() and sia_zone != 'N/A':
            logger.info(f"Sending SIA event in zone {sia_zone} for device {device_id}")
            send_sia_message(device_id, event_description, sia_zone, sia_config)
        else:
            logger.warning(f"No valid SIA zone for device {device_id}. Mapping: {mapping}")

def trigger_chekt_event(device_id, target_channel):
    """
    Trigger a CHEKT event on the given target channel with a fixed event description "Door opened".
    """
    from config import load_config
    import base64
    import requests

    config = load_config()
    chekt_config = config.get('chekt', {})
    ip = chekt_config.get('ip')
    port = chekt_config.get('port')
    api_token = chekt_config.get('api_token')

    logger.debug(f"CHEKT config: IP = {ip}, Port = {port}, API Token = {api_token}")
    if not ip or not port or not api_token:
        logger.error("CHEKT API configuration is incomplete (missing IP, port, or API token).")
        return

    # Use the /api/v1/events endpoint
    url = f"http://{ip}:{port}/api/v1/events"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode(f'apikey:{api_token}'.encode()).decode()}"
    }
    payload = {
        "target_channel": str(target_channel),
        "event_description": "Door opened"
    }

    logger.debug(f"Constructed URL: {url}")
    logger.debug(f"Constructed Payload: {payload}")
    logger.debug(f"Constructed Headers: {headers}")

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        logger.debug(f"HTTP Response status code: {response.status_code}")
        logger.debug(f"HTTP Response text: {response.text}")
        if response.status_code in [200, 201, 202]:
            logger.info(f"Successfully triggered CHEKT event for device {device_id} on target channel {target_channel}")
        else:
            logger.error(f"Failed to trigger CHEKT event: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        logger.exception(f"Error triggering CHEKT event for device {device_id}: {str(e)}")


def send_sia_message(device_id, event_description, zone, sia_config):
    logger.info(f"SIA message: {event_description} on zone {zone}")

