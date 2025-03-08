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

    # Get the primary receiver type
    receiver_type = config.get("receiver_type", "CHEKT").upper()
    if receiver_type not in ["CHEKT", "SIA", "MODBUS"]:
        logger.error(f"Invalid receiver type: {receiver_type}. Defaulting to CHEKT.")
        receiver_type = "CHEKT"

    # Get mapping for this device
    mapping = get_mapping(device_id)
    if not mapping:
        logger.warning(f"No mapping for device {device_id}")
        return

    event_description = map_state_to_event(state, device_type)
    logger.debug(f"Device {device_id} event description: {event_description}")

    # Process CHEKT if enabled and configured for this device
    if config.get("chekt", {}).get("enabled", True):
        chekt_zone = mapping.get('chekt_zone', 'N/A')
        if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
            logger.info(f"Triggering CHEKT event in zone {chekt_zone} for device {device_id}")
            trigger_chekt_event(device_id, chekt_zone)
        elif receiver_type == "CHEKT":
            logger.warning(
                f"Primary receiver is CHEKT but no valid CHEKT zone for device {device_id}. Mapping: {mapping}")

    # Process SIA if enabled and configured for this device
    if config.get("sia", {}).get("enabled", False):
        sia_zone = mapping.get('sia_zone', 'N/A')
        sia_config = config.get('sia', {})
        if sia_zone and sia_zone.strip() and sia_zone != 'N/A':
            logger.info(f"Sending SIA event in zone {sia_zone} for device {device_id}")
            send_sia_message(device_id, event_description, sia_zone, sia_config)
        elif receiver_type == "SIA":
            logger.warning(f"Primary receiver is SIA but no valid SIA zone for device {device_id}. Mapping: {mapping}")

    # Process Modbus relay if enabled and configured for this device
    if config.get("modbus", {}).get("enabled", False):
        relay_channel = mapping.get('relay_channel', 'N/A')
        # If relay channel is set, consider it enabled (no need to check use_relay flag)
        if relay_channel and relay_channel.strip() and relay_channel != 'N/A':
            try:
                relay_channel = int(relay_channel)
                logger.info(f"Triggering Modbus relay channel {relay_channel} for device {device_id}")
                trigger_modbus_relay(device_id, relay_channel, state)
            except ValueError:
                logger.error(f"Invalid relay channel: {relay_channel}. Must be a number.")
        elif receiver_type == "MODBUS":
            logger.warning(
                f"Primary receiver is MODBUS but no valid relay channel for device {device_id}. Mapping: {mapping}")


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


def trigger_modbus_relay(device_id, relay_channel, state):
    """
    Trigger a Modbus relay channel based on device state.
    Handles both pulse mode and follower mode based on configuration.

    Args:
        device_id (str): The device ID
        relay_channel (int): The relay channel number
        state (str): The device state
    """
    from config import load_config
    import modbus_relay

    config = load_config()
    modbus_config = config.get('modbus', {})

    # Only proceed if Modbus is enabled
    if not modbus_config.get('enabled', False):
        logger.info(f"Modbus relay is disabled in configuration. Not triggering relay for device {device_id}")
        return

    # Check if we're using follower mode
    follower_mode = modbus_config.get('follower_mode', False)

    # Validate input
    if not isinstance(relay_channel, int):
        try:
            relay_channel = int(relay_channel)
        except (ValueError, TypeError):
            logger.error(f"Invalid relay channel: {relay_channel}. Must be a number.")
            return

    # Get pulse seconds for pulse mode
    pulse_seconds = modbus_config.get('pulse_seconds', 1)

    # Determine relay state based on device state and mode
    if follower_mode:
        # In follower mode, relay state directly follows the sensor state
        if state in ['open', 'alert']:
            # For door sensors "open" or motion sensors "alert", turn relay ON
            activate = True
        else:
            # For other states (closed, normal), turn relay OFF
            activate = False

        # Set relay to match sensor state (no pulsing)
        logger.info(
            f"Follower mode: Setting relay channel {relay_channel} to {'ON' if activate else 'OFF'} for device {device_id} with state {state}")
        success = modbus_relay.trigger_relay(relay_channel, activate, follower_mode=True)
    else:
        # In pulse mode (default), we only activate the relay, not deactivate it
        if state in ['open', 'alert']:
            # For door sensors "open" or motion sensors "alert", activate the relay
            activate = True
        elif state == 'closed':
            # For door sensors "closed", don't activate the relay
            activate = False
        else:
            # For other states, default to activating
            logger.info(f"Unknown state: {state}. Defaulting to activating relay.")
            activate = True

        # Only trigger the relay if we're activating it (for pulse mode)
        if activate:
            logger.info(
                f"Pulse mode: Triggering relay channel {relay_channel} for device {device_id} with state {state}")
            success = modbus_relay.trigger_relay(relay_channel, True, pulse_seconds, follower_mode=False)
            if success:
                logger.info(f"Successfully triggered relay channel {relay_channel} for device {device_id}")
            else:
                logger.error(f"Failed to trigger relay channel {relay_channel} for device {device_id}")
        else:
            logger.info(f"Pulse mode: Not triggering relay for state: {state}")
            success = True

    return success


def send_sia_message(device_id, event_description, zone, sia_config):
    logger.info(f"SIA message: {event_description} on zone {zone}")