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
    and triggers alerts based on state changes. In follower mode, it tracks all relevant states;
    in pulse mode, it pulses the relay on alert conditions and resets on mode switch or restart.

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

        logger.debug(f"Received MQTT payload for {device_id}: {json.dumps(payload, indent=2)}")
        device = await get_device_data(device_id)
        if not device or "deviceId" not in device:
            logger.info(f"Initializing new device {device_id}")
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
            logger.info(f"State update for {device_id}: '{current_state}' -> '{new_state}'")
        else:
            logger.debug(f"No state change in payload for {device_id}, current state: {current_state}")

        if "battery" in data:
            battery_value = data["battery"]
            logger.debug(
                f"BEFORE: Raw battery value for {device_id}: {battery_value} (type: {type(battery_value).__name__})")

            if device["type"] in ["Hub", "Outlet", "Switch"] and battery_value is None:
                device["battery"] = "Powered"
            else:
                device["battery"] = map_battery_value(battery_value)

            logger.debug(
                f"AFTER: Mapped battery value for {device_id}: {device['battery']} (type: {type(device['battery']).__name__})")

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
            logger.error(f"Failed to save data for {device_id}: state={device.get('state')}")

        state = device.get("state", "unknown")
        config = await load_config()
        modbus_config = config.get("modbus", {})
        is_follower_mode = modbus_config.get("follower_mode", False)
        logger.debug(f"Processing {device_id} in {'follower' if is_follower_mode else 'pulse'} mode, state={state}")

        # Reset relay in pulse mode on first message after restart
        redis_client = await get_redis()
        reset_key = f"pulse_reset:{device_id}"
        if not is_follower_mode and not await redis_client.get(reset_key):
            logger.info(f"Resetting relay for {device_id} to OFF on pulse mode start")
            from alerts import trigger_modbus_relay
            mapping = await get_mapping(device_id)
            if mapping and mapping.get("use_relay", False):
                relay_channel = int(mapping.get("relay_channel", "1"))
                await trigger_modbus_relay(device_id, relay_channel, "closed")
                await redis_client.set(reset_key, "done", ex=3600)  # Expire in 1 hour

        # Trigger logic
        should_trigger = False
        if is_follower_mode:
            if state in ["open", "closed", "alert", "normal"]:
                should_trigger = True
                logger.debug(f"Follower mode: Triggering for {device_id}, state={state}")
        else:  # Pulse mode
            if state in ["open", "alert"] and current_state not in ["open", "alert"]:
                should_trigger = True
                logger.info(f"Pulse mode: Triggering pulse for {device_id} on transition to {state}")
            elif state in ["closed", "normal"]:
                logger.debug(f"Pulse mode: No action for {device_id} on {state}")

        if should_trigger:
            mapping = await get_mapping(device_id)
            if not mapping or not mapping.get("use_relay", False):
                logger.warning(f"No valid relay mapping for {device_id}")
                return
            device_type = {"DoorSensor": "door_contact", "MotionSensor": "motion", "LeakSensor": "leak_sensor"}.get(device["type"], "generic")
            relay_channel = int(mapping.get("relay_channel", "1"))
            try:
                from alerts import trigger_alert
                logger.info(f"Triggering alert for {device_id}: state={state}, type={device_type}, channel={relay_channel}")
                await trigger_alert(device_id, state, device_type)
            except Exception as e:
                logger.error(f"Failed to trigger alert for {device_id}: {e}", exc_info=True)
        else:
            logger.debug(f"No trigger needed for {device_id}: state={state}, previous={current_state}")

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
        logger.error(f"Invalid JSON payload: {e}")
    except Exception as e:
        logger.error(f"Error processing message for {device_id if 'device_id' in locals() else 'unknown'}: {e}", exc_info=True)


async def run_mqtt_client() -> None:
    global connected, mqtt_client, shutdown_event

    # Reset shutdown event if needed (in case of restart)
    if shutdown_event.is_set():
        shutdown_event = asyncio.Event()

    # Initialize state tracking
    redis_client = await get_redis()
    await redis_client.set("yolink_mqtt_status", "initializing")
    logger.info("Starting YoLink MQTT client")

    # Connection retry variables
    retry_count = 0
    max_retry_count = 100  # practically infinite, but avoid true infinite loop
    max_retry_delay = 60  # Maximum backoff in seconds
    credential_check_delay = 5  # Seconds between credential checks

    while not shutdown_event.is_set() and retry_count < max_retry_count:
        try:
            # Load configuration first - ADD THIS LINE
            config = await load_config()

            # 1. Check if credentials are available
            yolink_config = config.get("yolink", {})
            has_credentials = bool(yolink_config.get("uaid") and yolink_config.get("secret_key"))

            if not has_credentials:
                logger.info("YoLink credentials not configured, waiting...")
                await redis_client.set("yolink_mqtt_status", "credentials_missing")

                # Wait for shutdown or retry delay
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=credential_check_delay)
                    if shutdown_event.is_set():
                        logger.info("Shutdown requested during credential wait")
                        break
                except asyncio.TimeoutError:
                    retry_count += 1
                    continue

            # 2. Get access token for authentication
            token = await get_access_token()
            if not token:
                logger.error("Failed to obtain YoLink token, retrying...")
                await redis_client.set("yolink_mqtt_status", "token_error")

                # Calculate retry delay with exponential backoff
                retry_delay = min(max_retry_delay, 2 * (2 ** min(retry_count, 5)))
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=retry_delay)
                    if shutdown_event.is_set():
                        logger.info("Shutdown requested during token retry wait")
                        break
                except asyncio.TimeoutError:
                    retry_count += 1
                    continue

            # 3. Prepare MQTT connection
            mqtt_config = config.get("mqtt", {})
            topic = mqtt_config.get("topic", "yl-home/${Home ID}/+/report").replace("${Home ID}",
                                                                                    config.get("home_id", ""))

            # Log connection attempt (masking token)
            logger.info(
                f"Connecting to YoLink MQTT: url={mqtt_config.get('url')}, "
                f"port={mqtt_config.get('port')}, topic={topic}")

            # Update status in Redis
            await redis_client.set("yolink_mqtt_status", "connecting")

            # Extract hostname without protocol
            hostname = mqtt_config.get("url", "mqtt://api.yosmart.com").replace("mqtt://", "").replace("mqtts://", "")
            port = int(mqtt_config.get("port", 8003))

            # 4. Connect and process messages
            async with Client(
                    hostname=hostname,
                    port=port,
                    username=token,
                    keepalive=60
            ) as client:
                # Connection successful - update state
                mqtt_client = client
                connected = True
                retry_count = 0  # Reset retry counter on successful connection

                # Update status in Redis
                await redis_client.set("yolink_mqtt_status", "connected")
                await redis_client.set("yolink_mqtt_last_connected", asyncio.get_event_loop().time())
                await redis_client.set("yolink_mqtt_error", "")  # Clear any previous errors

                logger.info(f"Connected to YoLink MQTT, subscribing to {topic}")
                await client.subscribe(topic)

                # Process messages until shutdown requested
                async for message in client.messages:
                    try:
                        payload_str = message.payload.decode("utf-8")
                        payload = json.loads(payload_str)

                        # Process message in a separate task to prevent blocking
                        asyncio.create_task(process_message(payload))
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in MQTT message: {e}")
                    except Exception as e:
                        logger.error(f"Error processing MQTT message: {e}")

                    # Check for shutdown request
                    if shutdown_event.is_set():
                        logger.info("Shutdown requested, stopping MQTT processing")
                        break

                # When we exit the context manager, the client will be disconnected
                logger.info("MQTT client disconnected")

        except MqttError as e:
            # MQTT-specific errors (auth, connection, etc.)
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("yolink_mqtt_status", "disconnected")
            await redis_client.set("yolink_mqtt_error", str(e))

            # Handle authentication errors by refreshing the token on next attempt
            if "auth" in str(e).lower():
                logger.warning(f"Authentication error (attempt {retry_count}): {e}")
                # Force token refresh on next attempt by clearing from config
                config = await load_config()
                if "yolink" in config and "token" in config["yolink"]:
                    config["yolink"]["token"] = ""
                    config["yolink"]["issued_at"] = 0
                    config["yolink"]["expires_in"] = 0
                    await save_config(config)
            else:
                logger.error(f"MQTT connection error (attempt {retry_count}): {e}")

            # Calculate retry delay with exponential backoff and jitter
            base_delay = min(max_retry_delay, 2 * (2 ** min(retry_count - 1, 5)))
            jitter = 0.1 * base_delay * (0.9 + 0.2 * (hash(asyncio.get_event_loop().time()) % 10) / 10)
            retry_delay = base_delay + jitter

            logger.info(f"Retrying in {retry_delay:.1f} seconds (attempt {retry_count})...")

            # Wait for the delay or until shutdown is requested
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=retry_delay)
                if shutdown_event.is_set():
                    logger.info("Shutdown requested during reconnection delay")
                    break
            except asyncio.TimeoutError:
                pass  # Delay completed

        except Exception as e:
            # Other unexpected errors
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("yolink_mqtt_status", "error")
            await redis_client.set("yolink_mqtt_error", str(e))

            logger.error(f"Unexpected error in MQTT client (attempt {retry_count}): {e}", exc_info=True)

            # Shorter retry for unexpected errors
            retry_delay = min(max_retry_delay, 5)

            # Wait for the delay or until shutdown is requested
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=retry_delay)
                if shutdown_event.is_set():
                    logger.info("Shutdown requested during error reconnection delay")
                    break
            except asyncio.TimeoutError:
                pass  # Delay completed

    # Final cleanup
    connected = False
    mqtt_client = None

    if retry_count >= max_retry_count:
        await redis_client.set("yolink_mqtt_status", "failed_max_retries")
        logger.error(f"MQTT client giving up after {max_retry_count} attempts")
    else:
        await redis_client.set("yolink_mqtt_status", "shutdown")
        logger.info("Exiting YoLink MQTT client gracefully")

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
    global shutdown_event, connected, mqtt_client
    logger.info("Shutdown requested for YoLink MQTT client")
    shutdown_event.set()
    connected = False


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