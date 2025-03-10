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
import copy

# Import Redis manager
from redis_manager import get_redis
# Import important modules
from mappings import get_mapping

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


async def save_device_data(device_id: str, data: Dict[str, Any]) -> bool:
    """
    Save device data to Redis with proper error handling.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Device data to save

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from device_manager import save_device_data as save_device_impl
        return await save_device_impl(device_id, data)
    except Exception as e:
        logger.error(f"Error in save_device_data wrapper for {device_id}: {e}")
        return False


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


def map_battery_value(raw_value):
    """
    Map YoLink battery levels (0-4) to percentages.

    Args:
        raw_value: Raw battery level (0-4)

    Returns:
        Percentage value (0, 25, 50, 75, 100) or original if not in range 0-4
    """
    # For debug logging
    logger.debug(f"Mapping battery value: {raw_value} (type: {type(raw_value)})")

    # Handle common cases
    if raw_value is None:
        return "unknown"

    # Try to convert string to int if possible
    if isinstance(raw_value, str):
        try:
            raw_value = int(raw_value)
        except (ValueError, TypeError):
            return raw_value

    # Map 0-4 scale to percentages
    if isinstance(raw_value, int) or isinstance(raw_value, float):
        if 0 <= raw_value <= 4:
            battery_map = {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}
            return battery_map.get(raw_value, raw_value)
        # If it's already a percentage (>4), return it directly
        if 0 <= raw_value <= 100:
            return int(raw_value)

    # Default fallback
    return "unknown"


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


async def process_message(payload: dict) -> None:
    """
    Process an incoming MQTT message from a YoLink device asynchronously.

    This function extracts device data from the payload, updates the device's state in Redis,
    and triggers alerts based on state changes or specific alert conditions. In follower mode,
    it ensures alerts are triggered for all relevant states; in pulse mode, it triggers pulses
    on alert conditions and resets relays on startup if needed.

    Args:
        payload (dict): The MQTT message payload containing device data.

    Returns:
        None
    """
    try:
        device_id = payload.get("deviceId")
        if not device_id:
            logger.warning("Received MQTT payload without deviceId, skipping processing")
            return

        logger.debug(f"Processing MQTT message for device {device_id}: {json.dumps(payload, indent=2)}")
        device = await get_device_data(device_id)
        if not device or "deviceId" not in device:
            logger.info(f"Device {device_id} not found in Redis, creating new device entry")
            device = {
                "deviceId": device_id,
                "name": f"Device {device_id[-4:]}",
                "type": payload.get("type", "unknown"),
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

        data = payload.get("data", {})
        current_state = device.get("state", "unknown")
        if "state" in data:
            new_state = data["state"]
            device["previous_state"] = current_state
            device["state"] = new_state
            logger.debug(f"Device {device_id} state changed from '{current_state}' to '{new_state}'")

        if "battery" in data:
            battery_value = data["battery"]
            logger.debug(f"Raw battery value for {device_id}: {battery_value} (type: {type(battery_value)})")
            if device["type"] in ["Hub", "Outlet", "Switch"] and battery_value is None:
                device["battery"] = "Powered"
                logger.debug(f"Device {device_id} identified as mains-powered, battery set to 'Powered'")
            else:
                mapped_battery = map_battery_value(battery_value)
                device["battery"] = mapped_battery
                logger.debug(f"Battery for {device_id} mapped: {battery_value} -> {mapped_battery}")

        if "signal" in data:
            device["signal"] = data["signal"]
        elif "loraInfo" in data and "signal" in data["loraInfo"]:
            device["signal"] = data["loraInfo"]["signal"]
        device["temperature"] = data.get("temperature", device.get("temperature", "unknown"))
        device["humidity"] = data.get("humidity", device.get("humidity", "unknown"))
        device["temperatureUnit"] = data.get("temperatureUnit", device.get("temperatureUnit", "F"))
        if "alarm" in data:
            device["alarms"]["state"] = data["alarm"]
        if "type" in payload:
            device["type"] = payload["type"]
        device["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not await save_device_data(device_id, device):
            logger.error(f"Failed to save updated data for device {device_id}: state={device.get('state')}, "
                         f"previous_state={device.get('previous_state')}, battery={device.get('battery')}")

        state = device.get("state", "unknown")
        config = await load_config()
        modbus_config = config.get("modbus", {})
        is_follower_mode = modbus_config.get("follower_mode", False)
        logger.debug(f"Mode: {'follower' if is_follower_mode else 'pulse'}, State: {state}, Previous: {current_state}")

        # Reset relay state on first message after restart if in pulse mode
        redis_client = await get_redis()
        has_reset = await redis_client.get(f"pulse_reset:{device_id}")
        if not has_reset and not is_follower_mode:
            logger.info(f"Resetting relay for {device_id} to OFF on pulse mode startup")
            from alerts import trigger_modbus_relay
            mapping = await get_mapping(device_id)
            if mapping and mapping.get("use_relay", False):
                relay_channel = int(mapping.get("relay_channel", "1"))
                await trigger_modbus_relay(device_id, relay_channel, "closed")
                await redis_client.set(f"pulse_reset:{device_id}", "done")

        # Trigger logic
        should_trigger = False
        if is_follower_mode:
            if state in ["open", "closed", "alert", "normal"]:
                should_trigger = True
                logger.debug(f"Follower mode: Triggering for state '{state}' on {device_id}")
        else:  # Pulse mode
            if state in ["open", "alert"] and current_state not in ["open", "alert"]:
                should_trigger = True
                logger.info(f"Pulse mode: Triggering pulse for {device_id} on state change to {state}")

        if should_trigger:
            mapping = await get_mapping(device_id)
            if not mapping:
                logger.warning(f"No mapping for {device_id}, skipping alert")
                return
            device_type = {"DoorSensor": "door_contact", "MotionSensor": "motion", "LeakSensor": "leak_sensor"}.get(device["type"], "generic")
            try:
                from alerts import trigger_alert
                logger.info(f"Triggering alert for {device_id}: state={state}, type={device_type}")
                await trigger_alert(device_id, state, device_type)
            except Exception as e:
                logger.error(f"Alert trigger failed for {device_id}: {e}", exc_info=True)
        else:
            logger.debug(f"No trigger for {device_id}: state={state}, previous={current_state}")

        try:
            from monitor_mqtt import publish_update
            await publish_update(device_id, {
                "state": state,
                "alarms": device.get("alarms", {}),
                "signal": device.get("signal", "unknown"),
                "battery": device.get("battery", "unknown"),
                "last_seen": device.get("last_seen", "never")
            })
        except Exception as e:
            logger.error(f"Monitor update failed for {device_id}: {e}")

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in payload: {e}")
    except Exception as e:
        logger.error(f"Error processing message for {device_id if 'device_id' in locals() else 'unknown'}: {e}", exc_info=True)

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