"""
YoLink MQTT Client - Async Version
==================================

This module manages the YoLink MQTT connection for receiving
device status updates from YoLink devices and processing them.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from aiomqtt import Client, MqttError
from datetime import datetime
import aiohttp

# Import Redis manager
from redis_manager import get_redis

# Logging setup
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler("/app/logs/yolink.log", maxBytes=10 * 1024 * 1024, backupCount=5)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Global state
connected = False
mqtt_client: Optional[Client] = None
shutdown_event = asyncio.Event()


async def load_config() -> Dict[str, Any]:
    """
    Load application configuration asynchronously.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    from config import load_config as load_config_impl
    return await load_config_impl()


async def get_device_data(device_id: str) -> Optional[Dict[str, Any]]:
    """
    Get device data from Redis.

    Args:
        device_id (str): Device ID

    Returns:
        Optional[Dict[str, Any]]: Device data or None if not found
    """
    from device_manager import get_device_data as get_device_impl
    return await get_device_impl(device_id)  # Only device_id, no redis_client


async def save_device_data(device_id: str, data: Dict[str, Any]) -> None:
    """
    Save device data to Redis.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Device data to save
    """
    from device_manager import save_device_data as save_device_impl
    await save_device_impl(device_id, data)  # Only two arguments


async def get_access_token() -> Optional[str]:
    """
    Get a YoLink API access token, refreshing if needed.

    Returns:
        Optional[str]: Access token or None if unavailable
    """
    config = await load_config()
    from device_manager import get_access_token as token_impl
    return await token_impl(config)


async def has_valid_credentials() -> bool:
    """
    Check if the configuration has valid YoLink credentials.

    Returns:
        bool: True if credentials are present, False otherwise
    """
    config = await load_config()
    uaid = config.get("yolink", {}).get("uaid")
    secret_key = config.get("yolink", {}).get("secret_key")

    if not uaid or not secret_key or uaid == "" or secret_key == "":
        logger.info("YoLink credentials not yet configured. MQTT connection deferred.")
        return False
    return True


def map_battery_value(raw_value: int) -> Optional[int]:
    """
    Map YoLink battery levels (0-4) to percentages.

    Args:
        raw_value (int): Raw battery level (0-4)

    Returns:
        Optional[int]: Percentage value or None if invalid
    """
    if not isinstance(raw_value, int) or raw_value < 0 or raw_value > 4:
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}.get(raw_value)


def should_trigger_event(current_state: str, previous_state: str, device_type: str = None) -> bool:
    """
    Determine if an alert should be triggered based on state transitions or state="alert".

    Args:
        current_state (str): Current device state
        previous_state (str): Previous device state
        device_type (str, optional): Type of device

    Returns:
        bool: True if an alert should be triggered
    """
    logger.debug(f"Checking trigger: current_state={current_state}, previous_state={previous_state}")

    if current_state == "alert":
        logger.info("Triggering alert: state is 'alert'")
        return True

    if previous_state and current_state:
        if (previous_state == "open" and current_state == "closed") or \
                (previous_state == "closed" and current_state == "open"):
            logger.info(f"Triggering alert: state changed from '{previous_state}' to '{current_state}'")
            return True
    return False


async def process_message(payload: Dict[str, Any]) -> None:
    """
    Process incoming MQTT messages asynchronously.

    Args:
        payload (Dict[str, Any]): MQTT message payload
    """
    try:
        device_id = payload.get("deviceId")
        if not device_id:
            logger.warning("No deviceId in MQTT payload")
            return

        device = await get_device_data(device_id) or {}
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
                "previous_state": "unknown",
                "temperatureUnit": "F"
            }

        logger.debug(f"MQTT payload for {device_id}: {json.dumps(payload, indent=2)}")
        logger.debug(f"Current device data before update: {json.dumps(device, indent=2)}")

        data = payload.get("data", {})
        previous_state = device.get("state", "unknown")

        # Update state
        if "state" in data:
            device["state"] = data["state"]
            logger.debug(f"Updated state for device {device_id}: {previous_state} -> {device['state']}")

        # Improved battery handling
        if "battery" in data:
            raw_battery = data["battery"]
            logger.debug(f"Raw battery value for device {device_id}: {raw_battery}")

            # Handle different device types and their battery representation
            if isinstance(raw_battery, int) and 0 <= raw_battery <= 4:
                # Standard YoLink battery level (0-4)
                mapped_battery = map_battery_value(raw_battery)
                device["battery"] = mapped_battery
                logger.debug(f"Mapped battery value for device {device_id}: {raw_battery} -> {mapped_battery}%")
            elif device.get("type") in ["Hub", "Outlet", "Switch"] and raw_battery is None:
                # For mains-powered devices
                device["battery"] = None
                logger.debug(f"Device {device_id} is mains powered (battery=None)")
            elif isinstance(raw_battery, int) or isinstance(raw_battery, float):
                # Some devices might report actual percentage
                device["battery"] = int(raw_battery)
                logger.debug(f"Direct battery percentage for device {device_id}: {device['battery']}%")
            else:
                # Failed to parse battery level
                logger.warning(f"Unknown battery format for device {device_id}: {raw_battery}")
                device["battery"] = 'unknown'

        # Update signal
        if "signal" in data:
            device["signal"] = data["signal"]
        elif "loraInfo" in data and "signal" in data["loraInfo"]:
            device["signal"] = data["loraInfo"]["signal"]

        # Update other fields
        device["temperature"] = data.get("temperature", device.get("temperature", "unknown"))
        device["humidity"] = data.get("humidity", device.get("humidity", "unknown"))
        device["temperatureUnit"] = data.get("temperatureUnit", device.get("temperatureUnit", "F"))
        if "alarm" in data:
            device["alarms"]["state"] = data["alarm"]
        if "type" in payload:
            device["type"] = payload["type"]
        device["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save updated device data
        save_result = await save_device_data(device_id, device)
        if not save_result:
            logger.error(f"Failed to save device data for {device_id}")

        # Process alerts
        config = await load_config()
        from mappings import get_mapping
        mapping = await get_mapping(device_id)
        logger.debug(f"Mapping for device {device_id}: {mapping}")

        receiver_type = config.get("receiver_type", "CHEKT").upper()
        logger.debug(f"Receiver type: {receiver_type}")
        logger.debug(
            f"Device type: {device.get('type', 'unknown')}, State: {device['state']}, Previous State: {previous_state}")

        # Door sensor with prop alarm
        if device.get("type", "").lower() == "doorsensor" and mapping and mapping.get("door_prop_alarm", False):
            if data.get("alertType") == "openRemind":
                current_time = data.get("stateChangedAt") or data.get("time") or int(datetime.now().timestamp() * 1000)

                # Get last trigger time
                from alerts import get_last_door_prop_alarm, set_last_door_prop_alarm, trigger_chekt_event
                last_trigger = await get_last_door_prop_alarm(device_id)

                if last_trigger is None or (int(current_time) - int(last_trigger)) >= 30000:
                    await set_last_door_prop_alarm(device_id, current_time)
                    logger.info(
                        f"Door prop alarm triggered for device {device_id} on zone {mapping.get('chekt_zone')} at {current_time}")
                    await trigger_chekt_event(device_id, mapping.get("chekt_zone"))
                else:
                    wait_time = (30000 - (int(current_time) - int(last_trigger))) / 1000
                    logger.info(
                        f"Door prop alarm for device {device_id} not triggered; waiting {wait_time:.1f} seconds")
            else:
                logger.debug(
                    f"Door prop alarm conditions not met for {device_id} (prev: {previous_state}, current: {device['state']}, alertType: {data.get('alertType')})")
        elif mapping and should_trigger_event(device["state"], previous_state):
            # Always trigger alerts if conditions are met
            from alerts import trigger_alert
            logger.info(f"Triggering alert for device {device_id} with state {device['state']} (from {previous_state})")
            await trigger_alert(device_id, device["state"], device.get("type", "unknown"))

        # Publish update to Monitor MQTT
        from monitor_mqtt import publish_update
        await publish_update(device_id, {
            "state": device["state"],
            "alarms": device.get("alarms", {}),
            "battery": device["battery"],
            "signal": device["signal"],
            "temperature": device["temperature"],
            "humidity": device["humidity"],
            "type": device.get("type")
        })

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in MQTT payload: {e}")
    except Exception as e:
        logger.error(f"Error processing message for device {device_id if 'device_id' in locals() else 'unknown'}: {e}")
        logger.exception("Detailed error information:")


async def run_mqtt_client() -> None:
    """
    Run the YoLink MQTT client asynchronously with reconnection logic
    and graceful shutdown.
    """
    global connected, mqtt_client, shutdown_event

    # Check if credentials are available
    if not await has_valid_credentials():
        logger.info("YoLink MQTT connection deferred - waiting for credentials")
        connected = False

        # Update status in Redis
        redis_client = await get_redis()
        await redis_client.set("yolink_mqtt_status", "credentials_missing")

        return

    # Get access token for authentication
    token = await get_access_token()
    if not token:
        logger.error("Failed to obtain a valid YoLink token. Retrying in 5 seconds...")

        # Update status in Redis
        redis_client = await get_redis()
        await redis_client.set("yolink_mqtt_status", "token_error")

        await asyncio.sleep(5)
        await run_mqtt_client()
        return

    # Prepare to connect
    config = await load_config()
    mqtt_config = config["mqtt"]
    topic = mqtt_config["topic"].replace("${Home ID}", config["home_id"])
    logger.info(
        f"Attempting YoLink MQTT connection: url={mqtt_config['url']}, port={mqtt_config['port']}, token={'*' * len(token)}")

    # Update status in Redis
    redis_client = await get_redis()
    await redis_client.set("yolink_mqtt_status", "connecting")

    # Retry variables
    retry_count = 0
    max_retry_delay = 60  # Maximum retry delay in seconds

    while not shutdown_event.is_set():
        try:
            # Calculate retry delay with exponential backoff
            if retry_count > 0:
                # Exponential backoff with a small random factor
                base_delay = min(max_retry_delay, 1 * (2 ** (retry_count - 1)))
                # Add a small random factor to avoid reconnection storms
                jitter = 0.1 * base_delay * (0.9 + 0.2 * (hash(asyncio.get_event_loop().time()) % 10) / 10)
                delay = base_delay + jitter
                logger.info(f"Retrying YoLink MQTT connection in {delay:.1f} seconds (attempt {retry_count})...")

                # Wait for the delay or until shutdown is requested
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
                    if shutdown_event.is_set():
                        logger.info("Shutdown requested during reconnection delay")
                        break
                except asyncio.TimeoutError:
                    pass  # Delay completed

            # Extract hostname without protocol
            hostname = mqtt_config["url"].replace("mqtt://", "").replace("mqtts://", "")

            async with Client(
                    hostname=hostname,
                    port=mqtt_config["port"],
                    username=token,
                    keepalive=60
            ) as client:
                # Store client reference and update status
                mqtt_client = client
                connected = True
                retry_count = 0  # Reset retry counter on successful connection

                # Update status in Redis
                await redis_client.set("yolink_mqtt_status", "connected")
                await redis_client.set("yolink_mqtt_last_connected", asyncio.get_event_loop().time())

                logger.info(f"Connected to YoLink MQTT, subscribing to {topic}")
                await client.subscribe(topic)

                # Process messages until shutdown requested
                async for message in client.messages:
                    try:
                        payload_str = message.payload.decode("utf-8")
                        payload = json.loads(payload_str)

                        # Create a task to process the message asynchronously
                        # This allows us to continue receiving messages while processing
                        asyncio.create_task(process_message(payload))
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in MQTT message: {e}")
                    except Exception as e:
                        logger.error(f"Error processing MQTT message: {e}")

                    # Check if shutdown was requested
                    if shutdown_event.is_set():
                        break

        except MqttError as e:
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("yolink_mqtt_status", "disconnected")
            await redis_client.set("yolink_mqtt_error", str(e))

            logger.error(f"YoLink MQTT connection failed (attempt {retry_count}): {e}")
            if str(e).startswith("authentication"):
                logger.warning("Authentication failed, retrying with fresh token")
                token = await get_access_token()
                if not token:
                    logger.error("Failed to refresh token")

            # Check if shutdown was requested before retrying
            if shutdown_event.is_set():
                break

        except Exception as e:
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("yolink_mqtt_status", "error")
            await redis_client.set("yolink_mqtt_error", str(e))

            logger.error(f"Unexpected error in MQTT client (attempt {retry_count}): {e}")

            # Check if shutdown was requested before retrying
            if shutdown_event.is_set():
                break

    # Final cleanup
    connected = False
    mqtt_client = None
    await redis_client.set("yolink_mqtt_status", "shutdown")
    logger.info("Exiting YoLink MQTT client gracefully")


def is_connected() -> bool:
    """
    Check if the MQTT client is currently connected.

    Returns:
        bool: Connection status
    """
    global connected, mqtt_client
    return connected and mqtt_client is not None


def shutdown_yolink_mqtt() -> None:
    """
    Signal the YoLink MQTT loop to shutdown gracefully.
    This function can be called externally to stop the MQTT client.
    """
    global shutdown_event
    logger.info("Shutdown requested for YoLink MQTT client")
    shutdown_event.set()


async def get_status() -> Dict[str, Any]:
    """
    Get the current status of the YoLink MQTT client.

    Returns:
        Dict[str, Any]: Status information
    """
    try:
        redis_client = await get_redis()
        status = await redis_client.get("yolink_mqtt_status") or "unknown"
        last_connected = await redis_client.get("yolink_mqtt_last_connected")
        error = await redis_client.get("yolink_mqtt_error")

        return {
            "connected": connected,
            "status": status,
            "last_connected": float(last_connected) if last_connected else None,
            "error": error
        }
    except Exception as e:
        logger.error(f"Error getting YoLink MQTT status: {e}")
        return {
            "connected": connected,
            "status": "error",
            "error": str(e)
        }


# Example main function for testing
if __name__ == "__main__":
    async def main():
        # Set up logging
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        try:
            # Start the YoLink MQTT client
            mqtt_task = asyncio.create_task(run_mqtt_client())

            # Run for a limited time
            logger.info("YoLink MQTT client started, will run for 60 seconds")
            await asyncio.sleep(60)

            # Get and print status
            status = await get_status()
            logger.info(f"YoLink MQTT status: {json.dumps(status, indent=2)}")

        finally:
            # Shutdown gracefully
            logger.info("Shutting down YoLink MQTT client")
            shutdown_yolink_mqtt()
            await mqtt_task
            logger.info("YoLink MQTT client shutdown complete")


    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting")
    except Exception as e:
        print(f"Unhandled exception: {e}")