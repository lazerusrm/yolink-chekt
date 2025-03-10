"""
Monitor MQTT Client - Async Version
==================================

This module manages the Monitor MQTT connection for sending
device status updates to an external monitoring service.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from aiomqtt import Client, MqttError

# Import Redis manager
from redis_manager import get_redis

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Global state for MQTT
connected = False
mqtt_client: Optional[Client] = None
shutdown_event = asyncio.Event()


async def load_config() -> Dict[str, Any]:
    """
    Asynchronously load configuration.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    from config import load_config as load_config_impl
    return await load_config_impl()


async def run_monitor_mqtt() -> None:
    """
    Run the Monitor MQTT client with robust reconnection logic and graceful shutdown.
    """
    global connected, mqtt_client, shutdown_event

    # Reset shutdown event if needed (in case of restart)
    if shutdown_event.is_set():
        shutdown_event = asyncio.Event()

    # Initialize state
    redis_client = await get_redis()
    await redis_client.set("monitor_mqtt_status", "initializing")
    logger.info("Starting Monitor MQTT client")

    # Retry parameters
    retry_count = 0
    max_retry_count = 100  # practically infinite, but avoid true infinite loop
    max_retry_delay = 60  # Maximum backoff in seconds
    config_check_delay = 5  # Seconds between config checks

    while not shutdown_event.is_set() and retry_count < max_retry_count:
        try:
            # 1. Load configuration (always reload to catch changes)
            config = await load_config(use_cache=False)
            mqtt_config = config.get("mqtt_monitor", {})

            # 2. Check if configuration is valid
            has_url = bool(mqtt_config.get("url"))
            if not has_url:
                logger.info("Monitor MQTT URL not configured, waiting...")
                await redis_client.set("monitor_mqtt_status", "config_missing")

                # Wait for shutdown or retry
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=config_check_delay)
                    if shutdown_event.is_set():
                        logger.info("Shutdown requested during config wait")
                        break
                except asyncio.TimeoutError:
                    retry_count += 1
                    continue

            # 3. Log connection attempt
            logger.info(
                f"Connecting to Monitor MQTT: url={mqtt_config.get('url')}, "
                f"port={mqtt_config.get('port')}, "
                f"username={mqtt_config.get('username') or 'None'}, "
                f"password={'*****' if mqtt_config.get('password') else 'None'}"
            )

            # Update status
            await redis_client.set("monitor_mqtt_status", "connecting")

            # 4. Extract connection parameters
            hostname = mqtt_config.get("url", "mqtt://monitor.industrialcamera.com").replace("mqtt://", "").replace(
                "mqtts://", "")
            port = int(mqtt_config.get("port", 1883))
            username = mqtt_config.get("username") or None
            password = mqtt_config.get("password") or None
            client_id = mqtt_config.get("client_id", "monitor_client_id")

            # 5. Create MQTT connection
            async with Client(
                    hostname=hostname,
                    port=port,
                    identifier=client_id,
                    username=username,
                    password=password,
                    keepalive=60
            ) as client:
                # Connection successful - update state
                mqtt_client = client
                connected = True
                retry_count = 0  # Reset retry counter on successful connection

                # Update status in Redis
                await redis_client.set("monitor_mqtt_status", "connected")
                await redis_client.set("monitor_mqtt_last_connected", str(asyncio.get_event_loop().time()))
                await redis_client.set("monitor_mqtt_error", "")  # Clear any previous errors

                logger.info(f"Connected to Monitor MQTT at {hostname}:{port}")

                # Stay connected and check for shutdown periodically
                while not shutdown_event.is_set():
                    # Keep connection alive
                    try:
                        # Periodically ping to verify connection
                        await client.ping()
                        # Short wait between pings
                        await asyncio.sleep(30)
                    except MqttError as e:
                        logger.error(f"Error during Monitor MQTT ping: {e}")
                        break  # Break inner loop to trigger reconnection

                logger.info("Monitor MQTT client disconnecting")

        except MqttError as e:
            # MQTT-specific errors
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("monitor_mqtt_status", "disconnected")
            await redis_client.set("monitor_mqtt_error", str(e))

            # Handle authentication errors specially
            if "auth" in str(e).lower():
                logger.warning(f"Authentication failed for Monitor MQTT (attempt {retry_count}): {e}")
                logger.warning("Check username/password in configuration")
            else:
                logger.error(f"Monitor MQTT connection error (attempt {retry_count}): {e}")

            # Calculate backoff with jitter
            base_delay = min(max_retry_delay, 2 * (2 ** min(retry_count - 1, 5)))
            jitter = 0.1 * base_delay * (0.9 + 0.2 * (hash(asyncio.get_event_loop().time()) % 10) / 10)
            retry_delay = base_delay + jitter

            logger.info(f"Retrying Monitor MQTT in {retry_delay:.1f} seconds...")

            # Wait for delay or shutdown
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
            await redis_client.set("monitor_mqtt_status", "error")
            await redis_client.set("monitor_mqtt_error", str(e))

            logger.error(f"Unexpected error in Monitor MQTT client (attempt {retry_count}): {e}", exc_info=True)

            # Shorter retry for unexpected errors
            retry_delay = min(max_retry_delay, 5)

            # Wait for delay or shutdown
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=retry_delay)
                if shutdown_event.is_set():
                    logger.info("Shutdown requested during error recovery delay")
                    break
            except asyncio.TimeoutError:
                pass  # Delay completed

    # Final cleanup
    connected = False
    mqtt_client = None

    if retry_count >= max_retry_count:
        await redis_client.set("monitor_mqtt_status", "failed_max_retries")
        logger.error(f"Monitor MQTT client giving up after {max_retry_count} attempts")
    else:
        await redis_client.set("monitor_mqtt_status", "shutdown")
        logger.info("Exiting Monitor MQTT client gracefully")


async def publish_update(device_id: str, data: Dict[str, Any]) -> bool:
    """
    Publish an update to the Monitor MQTT topic with enhanced error handling.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Data to publish

    Returns:
        bool: Success status
    """
    global mqtt_client, connected

    if not device_id:
        logger.error("Cannot publish update: empty device_id")
        return False

    # Check connection status
    if not mqtt_client or not connected:
        logger.warning(f"Cannot publish update for device {device_id}: MQTT client not connected")
        return False

    topic = f"monitor/devices/{device_id}"
    try:
        # Add timestamp to data
        data["timestamp"] = int(asyncio.get_event_loop().time() * 1000)  # milliseconds

        # Sanitize data to ensure it can be serialized to JSON
        sanitized_data = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool, type(None))):
                sanitized_data[key] = value
            elif isinstance(value, dict):
                try:
                    # Test JSON serialization
                    json.dumps(value)
                    sanitized_data[key] = value
                except (TypeError, ValueError):
                    sanitized_data[key] = str(value)
            else:
                sanitized_data[key] = str(value)

        # Convert to JSON
        message_json = json.dumps(sanitized_data)

        # Publish with QoS 1 to ensure delivery
        await mqtt_client.publish(topic, message_json, qos=1)
        logger.debug(f"Published update for device {device_id}")
        return True
    except MqttError as e:
        logger.error(f"MQTT error publishing update for device {device_id}: {e}")
        connected = False  # Mark as disconnected to trigger reconnection
        return False
    except json.JSONDecodeError as e:
        logger.error(f"JSON serialization error for device {device_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error publishing update for device {device_id}: {e}", exc_info=True)
        return False


def is_connected() -> bool:
    """
    Check if the MQTT client is currently connected.

    Returns:
        bool: Connection status
    """
    global connected, mqtt_client
    return connected and mqtt_client is not None


def shutdown_monitor_mqtt() -> None:
    """
    Signal the Monitor MQTT loop to shutdown gracefully.
    This function can be called externally to stop the MQTT client.
    """
    global shutdown_event, connected, mqtt_client
    logger.info("Shutdown requested for Monitor MQTT client")
    shutdown_event.set()
    connected = False


async def get_status() -> Dict[str, Any]:
    """
    Get the current status of the Monitor MQTT client.

    Returns:
        Dict[str, Any]: Status information
    """
    try:
        redis_client = await get_redis()
        status = await redis_client.get("monitor_mqtt_status") or "unknown"
        last_connected = await redis_client.get("monitor_mqtt_last_connected")
        error = await redis_client.get("monitor_mqtt_error")

        return {
            "connected": connected,
            "status": status,
            "last_connected": float(last_connected) if last_connected else None,
            "error": error
        }
    except Exception as e:
        logger.error(f"Error getting Monitor MQTT status: {e}")
        return {
            "connected": connected,
            "status": "error",
            "error": str(e)
        }


# Example main for testing graceful shutdown
if __name__ == "__main__":
    async def main():
        # Set up logging
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Start the monitor MQTT task
        mqtt_task = asyncio.create_task(run_monitor_mqtt())

        try:
            # Run for a limited time then shut down (for testing purposes)
            logger.info("Monitor MQTT client started, will run for 30 seconds")
            await asyncio.sleep(30)

            # Test publishing (will only work if connected)
            if is_connected():
                test_data = {
                    "state": "open",
                    "battery": 75,
                    "signal": -85,
                    "test": True
                }
                success = await publish_update("test_device", test_data)
                logger.info(f"Test publish result: {success}")

            # Get and print status
            status = await get_status()
            logger.info(f"Monitor MQTT status: {json.dumps(status, indent=2)}")

        finally:
            logger.info("Shutting down Monitor MQTT client")
            shutdown_monitor_mqtt()
            await mqtt_task
            logger.info("Monitor MQTT client shutdown complete")


    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting")
    except Exception as e:
        print(f"Unhandled exception: {e}")