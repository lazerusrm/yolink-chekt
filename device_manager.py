"""
YoLink Device Manager - Async Version
====================================

This module manages YoLink device data, including:
  - Refreshing devices from the YoLink API
  - Cleaning up inactive devices
  - Mapping battery levels
  - Updating device state and mappings

All operations are fully asynchronous and use the centralized Redis manager.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union

import aiohttp
from redis.asyncio import Redis

# Import Redis manager
from redis_manager import get_redis

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Default timeout for API requests
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=10)


async def load_config() -> Dict[str, Any]:
    """
    Asynchronously load configuration.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    from config import load_config as load_config_impl
    return await load_config_impl()


def map_battery_value(raw_value: int) -> Optional[int]:
    """
    Map YoLink battery levels (0-4) to percentages.

    Args:
        raw_value (int): Raw battery level (0-4)

    Returns:
        Optional[int]: Percentage value or None if invalid
    """
    if not isinstance(raw_value, int) or not (0 <= raw_value <= 4):
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}.get(raw_value)


async def remove_device(device_id: str) -> None:
    """
    Remove a device from Redis by its device_id.

    Args:
        device_id (str): The device's identifier
    """
    try:
        redis_client = await get_redis()
        await redis_client.delete(f"device:{device_id}")
        logger.info(f"Removed inactive device {device_id}")
    except Exception as e:
        logger.error(f"Error removing device {device_id}: {e}")


async def cleanup_inactive_devices(days_threshold: int = 14) -> None:
    """
    Remove devices that haven't been seen in the specified number of days.

    Args:
        days_threshold (int): Number of days of inactivity before removal
    """
    try:
        cutoff_date = datetime.now() - timedelta(days=days_threshold)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Cleaning up devices not seen since {cutoff_str}")

        all_devices = await get_all_devices()
        devices_to_remove = []

        for device in all_devices:
            device_id = device.get("deviceId")
            last_seen = device.get("last_seen", "never")
            if not last_seen or last_seen == "never":
                logger.debug(f"Skipping device {device_id} with no last_seen data")
                continue
            try:
                last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if last_seen_date < cutoff_date:
                    logger.info(f"Device {device_id} (name: {device.get('name')}) last seen at {last_seen} will be removed")
                    devices_to_remove.append(device_id)
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse last_seen for {device_id}: {last_seen}. Error: {e}")

        if devices_to_remove:
            logger.info(f"Removing {len(devices_to_remove)} inactive devices")
            removal_tasks = [remove_device(device_id) for device_id in devices_to_remove]
            await asyncio.gather(*removal_tasks, return_exceptions=True)

            # Update mappings to remove references to deleted devices
            from mappings import get_mappings, save_mappings
            mappings = await get_mappings()
            original_count = len(mappings.get("mappings", []))
            mappings["mappings"] = [
                m for m in mappings.get("mappings", [])
                if m.get("yolink_device_id") not in devices_to_remove
            ]
            if len(mappings["mappings"]) != original_count:
                await save_mappings(mappings)
        else:
            logger.debug("No inactive devices to clean up")
    except Exception as e:
        logger.error(f"Error in inactive device cleanup: {e}")
        raise


async def get_access_token(config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Retrieve or refresh the YoLink access token asynchronously.

    Args:
        config (Dict[str, Any], optional): Configuration dictionary or None to load

    Returns:
        Optional[str]: Access token or None if fetching fails
    """
    if config is None:
        config = await load_config()

    current_time = datetime.now().timestamp()
    token = config["yolink"].get("token")
    issued_at = config["yolink"].get("issued_at", 0)
    expires_in = config["yolink"].get("expires_in", 0)

    # Check if we have a valid token
    if token and issued_at and expires_in:
        token_expiry = issued_at + expires_in - 300  # Expire 5 minutes early to be safe
        if current_time < token_expiry:
            logger.debug("Using existing YoLink token (still valid)")
            return token

    # Get new token
    url = "https://api.yosmart.com/open/yolink/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": config["yolink"]["uaid"],
        "client_secret": config["yolink"]["secret_key"]
    }

    try:
        async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
            async with session.post(url, data=payload) as response:
                if response.status != 200:
                    response_text = await response.text()
                    logger.error(f"Token request failed with status {response.status}: {response_text}")
                    return None

                data = await response.json()
                if "access_token" not in data or "expires_in" not in data:
                    logger.error(f"Invalid token response: {data}")
                    return None

                # Update config with new token details
                config["yolink"]["token"] = data["access_token"]
                config["yolink"]["issued_at"] = current_time
                config["yolink"]["expires_in"] = data["expires_in"]

                # Save updated config
                from config import save_config
                await save_config(config)

                logger.info("New YoLink token fetched and saved")
                return data["access_token"]
    except aiohttp.ClientError as e:
        logger.error(f"Failed to get access token: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting access token: {e}")
        return None


async def process_device(device: Dict[str, Any]) -> None:
    """
    Process and update a single device entry in Redis.

    Args:
        device (Dict[str, Any]): Device data from the API
    """
    device_id = device["deviceId"]
    existing = await get_device_data(device_id) or {}
    logger.debug(f"Processing device {device_id}: {device.get('name', 'Unknown')}")

    battery = device.get("battery", existing.get("battery", "unknown"))
    if isinstance(battery, int):
        battery = map_battery_value(battery)

    device_data = {
        "deviceId": device_id,
        "name": device.get("name", f"Device {device_id[-4:]}"),
        "type": device.get("type", "unknown"),
        "state": existing.get("state", "unknown"),
        "signal": device.get("loraInfo", {}).get("signal",
                    device.get("signal", existing.get("signal", "unknown"))),
        "battery": battery,
        "last_seen": existing.get("last_seen", "never"),
        "alarms": existing.get("alarms", {}),
        "temperature": device.get("temperature", existing.get("temperature", "unknown")),
        "humidity": device.get("humidity", existing.get("humidity", "unknown")),
        "temperatureUnit": device.get("temperatureUnit", existing.get("temperatureUnit", "F")),
        "previous_state": existing.get("previous_state", "unknown")
    }
    await save_device_data(device_id, device_data)
    logger.debug(f"Updated device {device_id} in Redis")


async def refresh_yolink_devices() -> bool:
    """
    Refresh all YoLink devices from the API and update Redis.

    This function:
      - Stores the last refresh timestamp
      - Retrieves an access token
      - Cleans up inactive devices
      - Fetches home information and device list concurrently
      - Updates device data and mappings

    Returns:
        bool: True if successful, False otherwise
    """
    redis_client = await get_redis()
    current_timestamp = datetime.now().timestamp()

    try:
        # Store refresh timestamp
        await redis_client.set("last_refresh_time", str(current_timestamp))
        logger.info("Starting YoLink device refresh")

        # Get access token
        config = await load_config()
        token = await get_access_token(config)
        if not token:
            logger.error("No valid token available; aborting device refresh")
            return False

        # Clean up inactive devices
        await cleanup_inactive_devices()

        # Prepare for API requests
        url = "https://api.yosmart.com/open/yolink/v2/api"
        headers = {"Authorization": f"Bearer {token}"}

        # Concurrent API requests for better performance
        async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
            # Prepare requests
            home_info_request = session.post(
                url,
                headers=headers,
                json={"method": "Home.getGeneralInfo"}
            )
            device_list_request = session.post(
                url,
                headers=headers,
                json={"method": "Home.getDeviceList"}
            )

            # Execute requests concurrently
            home_response, device_response = await asyncio.gather(
                home_info_request,
                device_list_request,
                return_exceptions=True
            )

            # Handle home info response
            if isinstance(home_response, Exception):
                logger.error(f"Failed to get home info: {home_response}")
                return False

            home_data = await home_response.json()
            if home_response.status != 200 or home_data.get("code") != "000000":
                logger.error(f"Failed to get home info: {home_data}")
                return False

            home_id = home_data["data"]["id"]
            if home_id != config.get("home_id"):
                config["home_id"] = home_id
                from config import save_config
                await save_config(config)
                logger.info(f"Updated home ID: {home_id}")

            # Handle device list response
            if isinstance(device_response, Exception):
                logger.error(f"Failed to get device list: {device_response}")
                return False

            device_data = await device_response.json()
            if device_response.status != 200 or device_data.get("code") != "000000":
                logger.error(f"Failed to get device list: {device_data}")
                return False

            devices = device_data["data"]["devices"]
            logger.info(f"Retrieved {len(devices)} devices from YoLink API")

            # Process devices concurrently
            await asyncio.gather(*[process_device(device) for device in devices])

            # Update mappings: add any new devices not already mapped
            from mappings import get_mappings, save_mappings
            mappings = await get_mappings()
            mapping_updated = False

            for device in devices:
                device_id = device["deviceId"]
                if not any(m.get("yolink_device_id") == device_id for m in mappings.get("mappings", [])):
                    mappings.setdefault("mappings", []).append({
                        "yolink_device_id": device_id,
                        "chekt_zone": "N/A",
                        "sia_zone": "N/A",
                        "relay_channel": "N/A",
                        "door_prop_alarm": False,
                        "use_relay": False
                    })
                    mapping_updated = True

            if mapping_updated:
                await save_mappings(mappings)
                logger.info("Updated mappings with new devices")

            # Store refresh completion time
            await redis_client.set("last_refresh_completed", str(datetime.now().timestamp()))
            logger.info(f"Refreshed {len(devices)} devices successfully")
            return True

    except aiohttp.ClientError as e:
        logger.error(f"API error during device refresh: {e}")
        return False
    except Exception as e:
        logger.exception(f"Error during device refresh: {e}")
        return False


async def get_all_devices() -> List[Dict[str, Any]]:
    """
    Retrieve all devices from Redis.

    Returns:
        List[Dict[str, Any]]: List of device dictionaries
    """
    try:
        redis_client = await get_redis()
        keys = await redis_client.keys("device:*")
        if not keys:
            return []

        # Get all devices in parallel
        device_jsons = await asyncio.gather(*[redis_client.get(key) for key in keys])
        devices = []

        for device_json in device_jsons:
            if not device_json:
                continue

            try:
                device = json.loads(device_json)
                devices.append(device)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse device JSON: {e}")

        logger.debug(f"Retrieved {len(devices)} devices from Redis")
        return devices
    except Exception as e:
        logger.error(f"Failed to get all devices: {e}")
        return []


async def get_device_data(device_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve device data from Redis.

    Args:
        device_id (str): Device ID

    Returns:
        Optional[Dict[str, Any]]: Device data or None if not found
    """
    try:
        redis_client = await get_redis()
        device_json = await redis_client.get(f"device:{device_id}")
        if device_json:
            device = json.loads(device_json)
            return device
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse device data for {device_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to get device data for {device_id}: {e}")
        return None


async def save_device_data(device_id: str, data: Dict[str, Any]) -> bool:
    """
    Save device data to Redis.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Device data to save

    Returns:
        bool: Success status
    """
    try:
        redis_client = await get_redis()

        # Check if state has changed
        existing = await get_device_data(device_id) or {}
        if "state" in data and existing.get("state") != data["state"]:
            data["previous_state"] = existing.get("state", "unknown")

        # Normalize battery
        if "battery" in data and isinstance(data["battery"], int) and 0 <= data["battery"] <= 4:
            data["battery"] = map_battery_value(data["battery"])

        # Save to Redis
        await redis_client.set(f"device:{device_id}", json.dumps(data))
        return True
    except Exception as e:
        logger.error(f"Failed to save device data for {device_id}: {e}")
        return False


async def update_device_state(device_id: str, payload: Dict[str, Any]) -> bool:
    """
    Update a device's state from an MQTT payload.

    Args:
        device_id (str): Device ID
        payload (Dict[str, Any]): MQTT payload with updated device data

    Returns:
        bool: Success status
    """
    try:
        device = await get_device_data(device_id) or {
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
            "temperatureUnit": "F",
            "previous_state": "unknown"
        }

        data = payload.get("data", {})
        previous_state = device.get("state", "unknown")

        # Update state
        if "state" in data:
            device["state"] = data["state"]

        # Update battery
        if "battery" in data:
            battery = data["battery"]
            if isinstance(battery, int) and 0 <= battery <= 4:
                device["battery"] = map_battery_value(battery)
            elif battery is None and device.get("type") in ["Hub", "Outlet", "Switch"]:
                device["battery"] = None
            else:
                device["battery"] = "unknown"

        # Update signal
        if "signal" in data:
            device["signal"] = data["signal"]
        elif "loraInfo" in data and "signal" in data["loraInfo"]:
            device["signal"] = data["loraInfo"]["signal"]

        # Update other fields
        if "temperature" in data:
            device["temperature"] = data["temperature"]
        if "humidity" in data:
            device["humidity"] = data["humidity"]
        if "temperatureUnit" in data:
            device["temperatureUnit"] = data["temperatureUnit"]
        if "alarm" in data:
            device.setdefault("alarms", {})["state"] = data["alarm"]
        if "type" in payload:
            device["type"] = payload["type"]

        # Update last seen timestamp
        device["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Track state change
        if previous_state != device["state"]:
            device["previous_state"] = previous_state

        # Save updated device
        return await save_device_data(device_id, device)
    except Exception as e:
        logger.error(f"Error updating device {device_id} state: {e}")
        return False


async def get_last_refresh_time() -> Optional[Dict[str, Any]]:
    """
    Get information about the last device refresh.

    Returns:
        Optional[Dict[str, Any]]: Refresh information or None
    """
    try:
        redis_client = await get_redis()
        last_refresh = await redis_client.get("last_refresh_time")
        last_completed = await redis_client.get("last_refresh_completed")

        if not last_refresh:
            return None

        last_refresh_time = float(last_refresh)
        last_completed_time = float(last_completed) if last_completed else None

        current_time = datetime.now().timestamp()
        minutes_ago = (current_time - last_refresh_time) / 60.0

        return {
            "timestamp": last_refresh_time,
            "completed_timestamp": last_completed_time,
            "formatted_time": datetime.fromtimestamp(last_refresh_time).strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_ago": round(minutes_ago, 1),
            "success": last_completed is not None
        }
    except Exception as e:
        logger.error(f"Error getting last refresh time: {e}")
        return None


# Test function
async def main():
    """Test the device manager functions."""
    import time

    # Set up logging
    logging.basicConfig(level=logging.DEBUG)

    try:
        # Test refresh
        logger.info("Testing device refresh...")
        start_time = time.time()
        success = await refresh_yolink_devices()
        elapsed = time.time() - start_time
        logger.info(f"Device refresh {'successful' if success else 'failed'} in {elapsed:.2f} seconds")

        # Get all devices
        devices = await get_all_devices()
        logger.info(f"Retrieved {len(devices)} devices")

        # Get refresh info
        refresh_info = await get_last_refresh_time()
        if refresh_info:
            logger.info(f"Last refresh: {refresh_info['formatted_time']} ({refresh_info['minutes_ago']} minutes ago)")

    except Exception as e:
        logger.exception(f"Error in main: {e}")
    finally:
        # Clean up Redis connection
        from redis_manager import close
        await close()


if __name__ == "__main__":
    asyncio.run(main())