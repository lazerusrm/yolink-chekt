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
    Run the Monitor MQTT client asynchronously with graceful shutdown
    and exponential backoff reconnection.
    """
    global connected, mqtt_client, shutdown_event

    config = await load_config()
    mqtt_config = config["mqtt_monitor"]
    logger.info(
        f"Attempting Monitor MQTT connection with config: "
        f"url={mqtt_config['url']}, username={mqtt_config['username']}, "
        f"password={'*' * len(mqtt_config['password']) if mqtt_config['password'] else 'None'}"
    )

    # Record status in Redis
    redis_client = await get_redis()
    await redis_client.set("monitor_mqtt_status", "connecting")

    # Continue to retry connection until a shutdown is requested
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
                logger.info(f"Retrying Monitor MQTT connection in {delay:.1f} seconds (attempt {retry_count})...")

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
                    client_id=mqtt_config["client_id"],
                    username=mqtt_config["username"] if mqtt_config["username"] else None,
                    password=mqtt_config["password"] if mqtt_config["password"] else None,
                    keepalive=60
            ) as client:
                mqtt_client = client  # Store the client for publishing
                connected = True
                retry_count = 0  # Reset retry counter on successful connection

                # Update status in Redis
                await redis_client.set("monitor_mqtt_status", "connected")
                await redis_client.set("monitor_mqtt_last_connected", asyncio.get_event_loop().time())

                logger.info(f"Connected to Monitor MQTT at {hostname}:{mqtt_config['port']}")

                # Keep the connection alive, but exit if a shutdown is requested
                while not shutdown_event.is_set():
                    # Periodically ping to ensure connection is still active
                    await asyncio.sleep(30)
                    # Optional: perform a ping or other keep-alive action

                # Exit the context, which will disconnect the client gracefully
                logger.info("Shutdown requested, disconnecting Monitor MQTT client")
                break  # Break out of the outer loop as well

        except MqttError as e:
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("monitor_mqtt_status", "disconnected")
            await redis_client.set("monitor_mqtt_error", str(e))

            logger.error(f"Monitor MQTT connection failed (attempt {retry_count}): {e}")
            if str(e).startswith("authentication"):
                logger.error("Authentication failed. Check username/password in config.")

        except Exception as e:
            connected = False
            mqtt_client = None
            retry_count += 1

            # Update status in Redis
            await redis_client.set("monitor_mqtt_status", "error")
            await redis_client.set("monitor_mqtt_error", str(e))

            logger.error(f"Unexpected error in Monitor MQTT client (attempt {retry_count}): {e}")

    # Final cleanup
    connected = False
    mqtt_client = None
    await redis_client.set("monitor_mqtt_status", "shutdown")
    logger.info("Exiting run_monitor_mqtt gracefully")


async def publish_update(device_id: str, data: Dict[str, Any]) -> bool:
    """
    Publish an update to the Monitor MQTT topic asynchronously.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Data to publish

    Returns:
        bool: Success status
    """
    global mqtt_client, connected

    if not mqtt_client or not connected:
        logger.warning(f"Cannot publish update for device {device_id}: MQTT client not connected")
        return False

    topic = f"monitor/devices/{device_id}"
    try:
        # Add timestamp to data
        data["timestamp"] = int(asyncio.get_event_loop().time() * 1000)  # milliseconds

        # Publish with QoS 1 to ensure delivery
        await mqtt_client.publish(topic, json.dumps(data), qos=1)
        logger.info(f"Published update for device {device_id}")
        return True
    except MqttError as e:
        logger.error(f"Failed to publish update for device {device_id}: {e}")
        # Queue for retry if needed
        return False
    except Exception as e:
        logger.error(f"Unexpected error publishing update for device {device_id}: {e}")
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
    global shutdown_event
    logger.info("Shutdown requested for Monitor MQTT client")
    shutdown_event.set()


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