import logging
import requests
import base64
from mappings import get_mapping

logger = logging.getLogger()

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

    if receiver_type == "CHEKT":
        chekt_zone = mapping.get('chekt_zone', 'N/A')
        if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
            logger.info(f"Triggering CHEKT event in zone {chekt_zone} for device {device_id}")
            trigger_chekt_event(device_id, event_description, chekt_zone)
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

def trigger_chekt_event(device_id, event_description, chekt_zone):
    from config import load_config
    config = load_config()
    chekt_config = config.get('chekt', {})
    ip = chekt_config.get('ip')
    port = chekt_config.get('port')
    api_token = chekt_config.get('api_token')

    if not all([ip, port, api_token]):
        logger.error("CHEKT API configuration is incomplete (missing IP, port, or API token).")
        return

    url = f"http://{ip}:{port}/channels/{chekt_zone}/events"
    auth_string = f"apikey:{api_token}"
    auth_header = base64.b64encode(auth_string.encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/json"
    }
    payload = {
        "event_description": event_description
    }

    # Add debug logs here:
    logger.debug(f"Triggering CHEKT event with URL: {url}")
    logger.debug(f"Payload: {payload}")
    logger.debug(f"Headers: {headers}")

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code in [200, 201, 202]:
            logger.info(f"Successfully triggered CHEKT event for device {device_id} on zone {chekt_zone}")
        else:
            logger.error(f"Failed to trigger CHEKT event: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error triggering CHEKT event for device {device_id}: {str(e)}")
