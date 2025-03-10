"""
YoLink Device Manager - Async Version (Enhanced)
================================================

Manages YoLink device data with async operations, including API refreshes,
Redis storage, and MQTT state updates for the Yolink to CHEKT integration.
"""

import asyncio
import json
import logging
import copy
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import aiohttp
from redis.asyncio import Redis

# Local imports
from redis_manager import get_redis
from config import load_config as load_config_impl, save_config
from mappings import get_mappings, save_mappings

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Default timeout for API requests
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=10)


def map_battery_value(raw_value: int) -> Optional[int]:
    """
    Map YoLink battery levels (0-4) to percentage values.

    Args:
        raw_value (int): Raw battery level (0-4)

    Returns:
        Optional[int]: Battery percentage (0, 25, 50, 75, 100) or None if invalid
    """
    battery_map = {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}
    return battery_map.get(raw_value) if isinstance(raw_value, int) and 0 <= raw_value <= 4 else None


async def load_config() -> Dict[str, Any]:
    """
    Load configuration asynchronously from the config module.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    return await load_config_impl()


async def remove_device(device_id: str) -> bool:
    """
    Remove a device from Redis by its device_id.

    Args:
        device_id (str): The device's identifier

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        redis_client = await get_redis()
        result = await redis_client.delete(f"device:{device_id}")
        if result:
            logger.info(f"Removed device {device_id} from Redis")
            return True
        logger.debug(f"Device {device_id} not found for removal")
        return False
    except Exception as e:
        logger.error(f"Error removing device {device_id}: {e}")
        return False


async def cleanup_inactive_devices(days_threshold: int = 14) -> int:
    """
    Remove devices inactive for more than the specified number of days.

    Args:
        days_threshold (int): Days of inactivity before removal (default: 14)

    Returns:
        int: Number of devices removed
    """
    try:
        cutoff_date = datetime.now() - timedelta(days=days_threshold)
        logger.info(f"Cleaning up devices inactive since {cutoff_date.strftime('%Y-%m-%d %H:%M:%S')}")

        all_devices = await get_all_devices()
        devices_to_remove = []

        for device in all_devices:
            device_id = device.get("deviceId")
            last_seen = device.get("last_seen", "never")
            if last_seen == "never":
                logger.debug(f"Skipping device {device_id} with no last_seen data")
                continue
            try:
                last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if last_seen_date < cutoff_date:
                    devices_to_remove.append(device_id)
                    logger.info(f"Marking device {device_id} (name: {device.get('name')}) for removal")
            except ValueError as e:
                logger.warning(f"Invalid last_seen for {device_id}: {last_seen}, error: {e}")

        if devices_to_remove:
            redis_client = await get_redis()
            removal_tasks = [redis_client.delete(f"device:{device_id}") for device_id in devices_to_remove]
            results = await asyncio.gather(*removal_tasks, return_exceptions=True)
            removed_count = sum(1 for r in results if r and not isinstance(r, Exception))

            # Update mappings
            mappings = await get_mappings()
            original_count = len(mappings.get("mappings", []))
            mappings["mappings"] = [
                m for m in mappings.get("mappings", [])
                if m.get("yolink_device_id") not in devices_to_remove
            ]
            if len(mappings["mappings"]) != original_count:
                await save_mappings(mappings)
                logger.info(f"Updated mappings, removed {original_count - len(mappings['mappings'])} entries")

            logger.info(f"Cleaned up {removed_count} inactive devices")
            return removed_count
        logger.debug("No inactive devices found to clean up")
        return 0
    except Exception as e:
        logger.error(f"Error during inactive device cleanup: {e}")
        return 0


async def get_access_token(config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Retrieve or refresh the YoLink access token asynchronously.

    Args:
        config (Optional[Dict[str, Any]]): Configuration dictionary; loads if None

    Returns:
        Optional[str]: Access token or None if fetching fails
    """
    if config is None:
        config = await load_config()

    current_time = datetime.now().timestamp()
    yolink_config = config.get("yolink", {})
    token = yolink_config.get("token")
    issued_at = yolink_config.get("issued_at", 0)
    expires_in = yolink_config.get("expires_in", 0)

    if token and issued_at and expires_in and current_time < (issued_at + expires_in - 300):
        logger.debug("Using valid existing YoLink token")
        return token

    url = "https://api.yosmart.com/open/yolink/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": yolink_config.get("uaid", ""),
        "client_secret": yolink_config.get("secret_key", "")
    }

    try:
        async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
            async with session.post(url, data=payload) as response:
                if response.status != 200:
                    logger.error(f"Token request failed: {response.status} - {await response.text()}")
                    return None
                data = await response.json()
                if "access_token" not in data or "expires_in" not in data:
                    logger.error(f"Invalid token response: {data}")
                    return None

                config["yolink"]["token"] = data["access_token"]
                config["yolink"]["issued_at"] = current_time
                config["yolink"]["expires_in"] = data["expires_in"]
                await save_config(config)
                logger.info("Refreshed YoLink access token")
                return data["access_token"]
    except aiohttp.ClientError as e:
        logger.error(f"Network error fetching token: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching token: {e}")
        return None


async def process_device(device: Dict[str, Any]) -> bool:
    """
    Process and update a single device entry in Redis.

    Args:
        device (Dict[str, Any]): Device data from the API

    Returns:
        bool: True if successful, False otherwise
    """
    try:
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
            "signal": device.get("loraInfo", {}).get("signal", existing.get("signal", "unknown")),
            "battery": battery,
            "last_seen": existing.get("last_seen", "never"),
            "alarms": existing.get("alarms", {}),
            "temperature": device.get("temperature", existing.get("temperature", "unknown")),
            "humidity": device.get("humidity", existing.get("humidity", "unknown")),
            "temperatureUnit": device.get("temperatureUnit", existing.get("temperatureUnit", "F")),
            "previous_state": existing.get("previous_state", "unknown")
        }
        return await save_device_data(device_id, device_data)
    except Exception as e:
        logger.error(f"Error processing device {device.get('deviceId', 'unknown')}: {e}")
        return False


async def refresh_yolink_devices() -> bool:
    """
    Refresh all YoLink devices from the API and update Redis.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        redis_client = await get_redis()
        current_timestamp = datetime.now().timestamp()

        await redis_client.set("last_refresh_time", str(current_timestamp))
        logger.info("Initiating YoLink device refresh")

        config = await load_config()
        token = await get_access_token(config)
        if not token:
            logger.error("Failed to obtain YoLink token")
            return False

        await cleanup_inactive_devices()

        url = "https://api.yosmart.com/open/yolink/v2/api"
        headers = {"Authorization": f"Bearer {token}"}

        async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
            home_task = session.post(url, headers=headers, json={"method": "Home.getGeneralInfo"})
            devices_task = session.post(url, headers=headers, json={"method": "Home.getDeviceList"})
            home_response, devices_response = await asyncio.gather(home_task, devices_task)

            # Process home info
            home_data = await home_response.json()
            if home_response.status != 200 or home_data.get("code") != "000000":
                logger.error(f"Home info request failed: {home_data}")
                return False
            home_id = home_data["data"]["id"]
            if home_id != config.get("home_id"):
                config["home_id"] = home_id
                await save_config(config)
                logger.info(f"Updated home ID to {home_id}")

            # Process device list
            devices_data = await devices_response.json()
            if devices_response.status != 200 or devices_data.get("code") != "000000":
                logger.error(f"Device list request failed: {devices_data}")
                return False
            devices = devices_data["data"]["devices"]
            logger.info(f"Fetched {len(devices)} devices from YoLink API")

            # Update devices
            results = await asyncio.gather(*[process_device(device) for device in devices], return_exceptions=True)
            if any(isinstance(r, Exception) for r in results):
                logger.error("Some devices failed to process")
                return False

            # Update mappings
            mappings = await get_mappings()
            mappings_list = mappings.setdefault("mappings", [])
            new_devices = [d["deviceId"] for d in devices if d["deviceId"] not in [m["yolink_device_id"] for m in mappings_list]]
            for device_id in new_devices:
                mappings_list.append({
                    "yolink_device_id": device_id,
                    "chekt_zone": "N/A",
                    "sia_zone": "N/A",
                    "relay_channel": "N/A",
                    "door_prop_alarm": False,
                    "use_relay": False
                })
            if new_devices:
                await save_mappings(mappings)
                logger.info(f"Added {len(new_devices)} new devices to mappings")

            await redis_client.set("last_refresh_completed", str(datetime.now().timestamp()))
            logger.info(f"Completed refresh of {len(devices)} devices")
            return True
    except Exception as e:
        logger.error(f"Device refresh failed: {e}")
        return False


async def get_all_devices() -> List[Dict[str, Any]]:
    """
    Retrieve all devices from Redis with retry logic.

    Returns:
        List[Dict[str, Any]]: List of device dictionaries
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.debug("Fetching Redis client for get_all_devices")
            redis_client = await get_redis()
            logger.debug("Fetching device keys")
            keys = await redis_client.keys("device:*")
            logger.debug(f"Found {len(keys)} device keys")
            if not keys:
                logger.debug("No devices found in Redis")
                return []

            device_jsons = await asyncio.gather(*[redis_client.get(key) for key in keys])
            devices = [json.loads(dj) for dj in device_jsons if dj]
            logger.debug(f"Retrieved {len(devices)} devices from Redis")
            return devices
        except Exception as e:
            logger.error(f"Error retrieving all devices (attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            if attempt < max_retries - 1:
                await asyncio.sleep(1)  # Delay before retry
            else:
                logger.error("All retries exhausted for get_all_devices")
                return []


async def get_device_data(device_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve device data from Redis by device_id.

    Args:
        device_id (str): Device ID

    Returns:
        Optional[Dict[str, Any]]: Device data or None if not found
    """
    try:
        redis_client = await get_redis()
        device_json = await redis_client.get(f"device:{device_id}")
        return json.loads(device_json) if device_json else None
    except Exception as e:
        logger.error(f"Error retrieving device {device_id}: {e}")
        return None


async def save_device_data(device_id: str, data: Dict[str, Any]) -> bool:
    """
    Save device data to Redis with robust error handling and retry logic.

    Args:
        device_id (str): Device ID
        data (Dict[str, Any]): Device data to save

    Returns:
        bool: True if successful, False otherwise
    """
    max_retries = 3

    # Create a deep copy to avoid modifying the original data
    device_data = copy.deepcopy(data)

    for attempt in range(max_retries):
        try:
            redis_client = await get_redis()
            existing = await get_device_data(device_id) or {}

            # Ensure we have proper state and previous_state tracking
            if "state" in device_data and device_data["state"] != existing.get("state"):
                device_data["previous_state"] = existing.get("state", "unknown")

            # Handle battery value mapping if needed
            if "battery" in device_data and device_data["battery"] is not None:
                # For numeric battery values on scale 0-4
                if isinstance(device_data["battery"], (int, float)) and 0 <= device_data["battery"] <= 4:
                    battery_map = {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}
                    device_data["battery"] = battery_map.get(int(device_data["battery"]))
                # For direct percentage values (0-100)
                elif isinstance(device_data["battery"], (int, float)) and 0 <= device_data["battery"] <= 100:
                    device_data["battery"] = int(device_data["battery"])
            elif "battery" in device_data and device_data["battery"] is None:
                # For recognized battery devices, map null to "unknown"
                if device_data.get("type") in ["DoorSensor", "MotionSensor", "LeakSensor", "THSensor",
                                               "COSmokeSensor", "VibrationSensor", "SmartRemoter"]:
                    device_data["battery"] = "unknown"

            # Validate data for any null bytes or control characters that would cause Redis issues
            for key, value in dict(device_data).items():
                if isinstance(value, str) and ('\x00' in value or any(ord(c) < 32 for c in value)):
                    logger.warning(f"Invalid character in {key} for device {device_id}, sanitizing")
                    device_data[key] = ''.join(c for c in value if ord(c) >= 32 and c != '\x00')

            # Ensure data can be serialized to JSON
            try:
                json_data = json.dumps(device_data)
            except (TypeError, ValueError) as json_error:
                logger.error(f"JSON serialization error for device {device_id}: {json_error}")
                logger.debug(f"Problematic data: {device_data}")

                # Fall back to sanitized version
                sanitized_data = {}
                for k, v in device_data.items():
                    try:
                        json.dumps({k: v})  # Test if this key-value pair can be serialized
                        sanitized_data[k] = v
                    except (TypeError, ValueError):
                        sanitized_data[k] = str(v)  # Convert to string as fallback

                json_data = json.dumps(sanitized_data)
                logger.debug(f"Using sanitized data for device {device_id}")

            # Set the data in Redis
            await redis_client.set(f"device:{device_id}", json_data)
            logger.debug(f"Saved device data for {device_id}")
            return True

        except Exception as e:
            # Log detailed exception information
            logger.error(f"Error saving device {device_id} (attempt {attempt + 1}/{max_retries}): {e}", exc_info=True)

            if attempt < max_retries - 1:
                # Exponential backoff before retrying
                await asyncio.sleep(0.5 * (attempt + 1))
            else:
                logger.error(f"All attempts to save device {device_id} failed")
                return False


async def update_device_state(device_id: str, payload: Dict[str, Any]) -> bool:
    """
    Update a device's state from an MQTT payload.

    Args:
        device_id (str): Device ID
        payload (Dict[str, Any]): MQTT payload with updated data

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        device = await get_device_data(device_id) or {
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
            "temperatureUnit": "F",
            "previous_state": "unknown"
        }

        data = payload.get("data", {})
        device["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update state with extra logging
        if "state" in data:
            device["previous_state"] = device.get("state", "unknown")
            device["state"] = data["state"]
            logger.debug(f"Updated state for device {device_id}: {device['previous_state']} -> {device['state']}")

        # Better battery handling with explicit logging
        if "battery" in data:
            raw_battery = data["battery"]
            logger.debug(f"Raw battery value for device {device_id}: {raw_battery}")

            if isinstance(raw_battery, int) and 0 <= raw_battery <= 4:
                mapped_battery = map_battery_value(raw_battery)
                device["battery"] = mapped_battery
                logger.debug(f"Mapped battery value for device {device_id}: {raw_battery} -> {mapped_battery}%")
            elif raw_battery is None:
                # For powered devices
                device["battery"] = None
                logger.debug(f"Device {device_id} is mains powered (battery=None)")
            else:
                # Unknown battery state
                logger.warning(f"Unexpected battery value for device {device_id}: {raw_battery}")
                device["battery"] = raw_battery  # Store original value for debugging

        # Update signal
        if "signal" in data:
            device["signal"] = data["signal"]
        elif "loraInfo" in data:
            device["signal"] = data["loraInfo"].get("signal", device["signal"])

        # Update temperature and humidity
        if "temperature" in data:
            device["temperature"] = data["temperature"]
        if "humidity" in data:
            device["humidity"] = data["humidity"]
        if "temperatureUnit" in data:
            device["temperatureUnit"] = data["temperatureUnit"]

        # Update alarms
        if "alarm" in data:
            device["alarms"]["state"] = data["alarm"]

        # Update device type if available
        if "type" in payload:
            device["type"] = payload["type"]

        return await save_device_data(device_id, device)
    except Exception as e:
        logger.error(f"Error updating device {device_id} state: {e}")
        return False


async def get_last_refresh_time() -> Optional[Dict[str, Any]]:
    """
    Get information about the last device refresh.

    Returns:
        Optional[Dict[str, Any]]: Refresh info or None if not available
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

        return {
            "timestamp": last_refresh_time,
            "completed_timestamp": last_completed_time,
            "formatted_time": datetime.fromtimestamp(last_refresh_time).strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_ago": round((current_time - last_refresh_time) / 60.0, 1),
            "success": last_completed_time is not None
        }
    except Exception as e:
        logger.error(f"Error getting last refresh time: {e}")
        return None


if __name__ == "__main__":
    async def test_device_manager():
        """Test the device manager functionality."""
        logging.basicConfig(level=logging.DEBUG)
        try:
            success = await refresh_yolink_devices()
            print(f"Device refresh: {'Success' if success else 'Failed'}")
            devices = await get_all_devices()
            print(f"Retrieved {len(devices)} devices")
            if devices:
                device_id = devices[0]["deviceId"]
                await update_device_state(device_id, {"data": {"state": "test"}})
                print(f"Updated state for {device_id}: {await get_device_data(device_id)}")
            refresh_info = await get_last_refresh_time()
            print(f"Last refresh: {refresh_info}")
        finally:
            from redis_manager import close
            await close()

    asyncio.run(test_device_manager())