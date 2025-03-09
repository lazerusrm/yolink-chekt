"""
YoLink Alerts Module - Async Version
===================================

This module handles alerts from YoLink devices and routes them to the
appropriate receiver (CHEKT, SIA, or Modbus relay).
"""

import logging
import base64
import aiohttp
import asyncio
from typing import Dict, Any, Optional

# Import the Redis manager instead of direct Redis client
from redis_manager import get_redis

logger = logging.getLogger(__name__)


# Forward mapping functions
async def get_mapping(device_id: str) -> Dict[str, Any]:
    """
    Asynchronously get mapping information for a device.

    Args:
        device_id (str): The device ID to get mapping for

    Returns:
        Dict[str, Any]: Mapping information
    """
    from mappings import get_mapping as get_mapping_impl
    return await get_mapping_impl(device_id)


async def load_config() -> Dict[str, Any]:
    """
    Asynchronously load configuration.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    from config import load_config as load_config_impl
    return await load_config_impl()


def map_state_to_event(state: str, device_type: str) -> str:
    """
    Map device state to human-readable event description.

    Args:
        state (str): Device state (open, closed, alert)
        device_type (str): Type of device (door_contact, motion, leak_sensor)

    Returns:
        str: Human-readable event description
    """
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


async def get_last_door_prop_alarm(device_id: str) -> Optional[int]:
    """
    Retrieve the last door prop alarm trigger time (in ms) for a given device from Redis.

    Args:
        device_id (str): Device identifier

    Returns:
        Optional[int]: Timestamp in ms or None if not found
    """
    redis_client = await get_redis()
    key = f"door_prop_alarm:{device_id}"
    ts = await redis_client.get(key)
    return int(ts) if ts else None


async def set_last_door_prop_alarm(device_id: str, timestamp: int) -> None:
    """
    Set the door prop alarm trigger time (in ms) for a given device in Redis.

    Args:
        device_id (str): Device identifier
        timestamp (int): Timestamp in milliseconds
    """
    redis_client = await get_redis()
    key = f"door_prop_alarm:{device_id}"
    await redis_client.set(key, str(timestamp))


async def trigger_alert(device_id: str, state: str, device_type: str) -> None:
    """
    Trigger an alert for a given device.

    This function checks configuration and mapping, then routes the alert
    to CHEKT, SIA, or Modbus relay as configured.

    Args:
        device_id (str): Device identifier
        state (str): Current device state (open, closed, alert)
        device_type (str): Type of device
    """
    config = await load_config()
    receiver_type = config.get("receiver_type", "CHEKT").upper()
    if receiver_type not in ["CHEKT", "SIA", "MODBUS"]:
        logger.error(f"Invalid receiver type: {receiver_type}. Defaulting to CHEKT.")
        receiver_type = "CHEKT"

    mapping = await get_mapping(device_id)
    if not mapping:
        logger.warning(f"No mapping for device {device_id}")
        return

    event_description = map_state_to_event(state, device_type)
    logger.debug(f"Device {device_id} event description: {event_description}")

    # Process alerts based on the configured primary receiver type
    if receiver_type == "CHEKT":
        # Process CHEKT if enabled and properly configured
        if config.get("chekt", {}).get("enabled", True):
            chekt_zone = mapping.get('chekt_zone', 'N/A')
            if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
                logger.info(f"Triggering CHEKT event in zone {chekt_zone} for device {device_id}")
                await trigger_chekt_event(device_id, chekt_zone)
            else:
                logger.warning(
                    f"Primary receiver is CHEKT but no valid CHEKT zone for device {device_id}. Mapping: {mapping}")

    elif receiver_type == "SIA":
        # Process SIA if enabled and properly configured
        if config.get("sia", {}).get("enabled", False):
            sia_zone = mapping.get('sia_zone', 'N/A')
            sia_config = config.get('sia', {})
            if sia_zone and sia_zone.strip() and sia_zone != 'N/A':
                logger.info(f"Sending SIA event in zone {sia_zone} for device {device_id}")
                await send_sia_message(device_id, event_description, sia_zone, sia_config)
            else:
                logger.warning(
                    f"Primary receiver is SIA but no valid SIA zone for device {device_id}. Mapping: {mapping}")

    # ALWAYS process Modbus relays if enabled and mapped, regardless of primary receiver type
    if config.get("modbus", {}).get("enabled", False):
        relay_channel = mapping.get('relay_channel', 'N/A')
        use_relay = mapping.get('use_relay', False)

        # Check both relay_channel and use_relay flag
        if relay_channel and relay_channel.strip() and relay_channel != 'N/A' and use_relay:
            try:
                relay_channel = int(relay_channel)
                logger.info(
                    f"Triggering Modbus relay channel {relay_channel} for device {device_id} (regardless of primary receiver)")
                await trigger_modbus_relay(device_id, relay_channel, state)
            except ValueError:
                logger.error(f"Invalid relay channel: {relay_channel}. Must be a number.")
        elif receiver_type == "MODBUS":
            if not use_relay:
                logger.warning(f"Primary receiver is MODBUS but use_relay is not enabled for device {device_id}")
            elif not relay_channel or relay_channel == 'N/A':
                logger.warning(
                    f"Primary receiver is MODBUS but no valid relay channel for device {device_id}. Mapping: {mapping}")

    # Additionally, if primary is not CHEKT or SIA but those are enabled, send alerts to them as well
    if receiver_type != "CHEKT" and config.get("chekt", {}).get("enabled", True):
        chekt_zone = mapping.get('chekt_zone', 'N/A')
        if chekt_zone and chekt_zone.strip() and chekt_zone != 'N/A':
            logger.info(
                f"Also triggering CHEKT event in zone {chekt_zone} for device {device_id} (additional receiver)")
            await trigger_chekt_event(device_id, chekt_zone)

    if receiver_type != "SIA" and config.get("sia", {}).get("enabled", False):
        sia_zone = mapping.get('sia_zone', 'N/A')
        sia_config = config.get('sia', {})
        if sia_zone and sia_zone.strip() and sia_zone != 'N/A':
            logger.info(f"Also sending SIA event in zone {sia_zone} for device {device_id} (additional receiver)")
            await send_sia_message(device_id, event_description, sia_zone, sia_config)

async def trigger_chekt_event(device_id: str, target_channel: str) -> None:
    """
    Trigger a CHEKT event on the given target channel.

    Uses aiohttp to asynchronously send the request with a fixed 
    event description "Door opened".

    Args:
        device_id (str): Device identifier
        target_channel (str): CHEKT zone/channel
    """
    config = await load_config()
    chekt_config = config.get('chekt', {})
    ip = chekt_config.get('ip')
    port = chekt_config.get('port')
    api_token = chekt_config.get('api_token')

    logger.debug(f"CHEKT config: IP = {ip}, Port = {port}, API Token = {api_token}")
    if not ip or not port or not api_token:
        logger.error("CHEKT API configuration is incomplete (missing IP, port, or API token).")
        return

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
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=10) as response:
                logger.debug(f"HTTP Response status code: {response.status}")
                text = await response.text()
                logger.debug(f"HTTP Response text: {text}")
                if response.status in [200, 201, 202]:
                    logger.info(
                        f"Successfully triggered CHEKT event for device {device_id} on target channel {target_channel}")
                else:
                    logger.error(f"Failed to trigger CHEKT event: {response.status} - {text}")
    except Exception as e:
        logger.exception(f"Error triggering CHEKT event for device {device_id}: {str(e)}")


async def trigger_modbus_relay(device_id: str, relay_channel: int, state: str) -> bool:
    """
    Trigger a Modbus relay channel based on device state.

    Handles both pulse mode and follower mode as per configuration.

    Args:
        device_id (str): Device identifier
        relay_channel (int): Relay channel number
        state (str): Device state (open, closed, alert)

    Returns:
        bool: Success status
    """
    config = await load_config()
    modbus_config = config.get('modbus', {})

    if not modbus_config.get('enabled', False):
        logger.info(f"Modbus relay is disabled in configuration. Not triggering relay for device {device_id}")
        return False

    # Import here to avoid circular imports
    from modbus_relay import trigger_relay

    follower_mode = modbus_config.get('follower_mode', False)
    pulse_seconds = modbus_config.get('pulse_seconds', 1)

    if follower_mode:
        activate = state in ['open', 'alert']
        logger.info(
            f"Follower mode: Setting relay channel {relay_channel} to {'ON' if activate else 'OFF'} for device {device_id} with state {state}")
        success = await trigger_relay(relay_channel, activate)
    else:
        if state in ['open', 'alert']:
            activate = True
        elif state == 'closed':
            activate = False
        else:
            logger.info(f"Unknown state: {state}. Defaulting to activating relay.")
            activate = True

        if activate:
            logger.info(
                f"Pulse mode: Triggering relay channel {relay_channel} for device {device_id} with state {state}")
            success = await trigger_relay(relay_channel, True, pulse_seconds)
            if success:
                logger.info(f"Successfully triggered relay channel {relay_channel} for device {device_id}")
            else:
                logger.error(f"Failed to trigger relay channel {relay_channel} for device {device_id}")
        else:
            logger.info(f"Pulse mode: Not triggering relay for state: {state}")
            success = True

    return success


async def send_sia_message(device_id: str, event_description: str, zone: str, sia_config: Dict[str, Any]) -> None:
    """
    Send an SIA message asynchronously.

    For now, this function logs the event. 
    Expand with real implementation as needed.

    Args:
        device_id (str): Device identifier
        event_description (str): Description of the event
        zone (str): SIA zone
        sia_config (Dict[str, Any]): SIA configuration
    """
    logger.info(f"SIA message: {event_description} on zone {zone}")
    # Placeholder: implement actual SIA messaging here if required.
    await asyncio.sleep(0)  # Dummy await to mark function as async


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


    async def test():
        # Test trigger_chekt_event
        await trigger_chekt_event("test_device_id", "1")


    asyncio.run(test())