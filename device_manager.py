import requests
import time
import json
import logging
from config import load_config, save_config
from db import redis_client
from mappings import get_mappings, save_mappings

logger = logging.getLogger(__name__)


def map_battery_value(raw_value):
    """Map YoLink battery levels (0-4) to percentages."""
    if not isinstance(raw_value, int) or raw_value < 0 or raw_value > 4:
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}[raw_value]


def get_access_token(config):
    """Retrieve or refresh the YoLink access token, validating its age."""
    current_time = time.time()
    issued_at = config["yolink"].get("issued_at", 0)  # When token was issued
    expires_in = config["yolink"].get("expires_in", 0)  # Token lifetime in seconds
    token_expiry = issued_at + expires_in  # Calculated expiration time

    # Check if token is still valid based on issuance time and duration
    if issued_at and expires_in and current_time < token_expiry:
        logger.debug("Token still valid, using existing token.")
        return config["yolink"]["token"]

    # Token is expired or not present, fetch a new one
    url = "https://api.yosmart.com/open/yolink/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": config["yolink"]["uaid"],
        "client_secret": config["yolink"]["secret_key"]
    }
    try:
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "access_token" not in data or "expires_in" not in data:
            logger.error(f"Invalid token response: {data}")
            return None
        # Update config with new token details
        config["yolink"]["token"] = data["access_token"]
        config["yolink"]["issued_at"] = current_time  # Store issuance time
        config["yolink"]["expires_in"] = data["expires_in"]  # Store duration
        config["yolink"]["token_expiry"] = current_time + data["expires_in"]  # Store for reference
        save_config(config)
        logger.info("New YoLink token fetched and saved.")
        return data["access_token"]
    except requests.RequestException as e:
        logger.error(f"Failed to get access token: {e}")
        return None


def refresh_yolink_devices():
    """Refresh all YoLink devices from the API and update Redis with enhanced data."""
    config = load_config()
    token = get_access_token(config)
    if not token:
        logger.error("No valid token available; aborting device refresh")
        return
    url = "https://api.yosmart.com/open/yolink/v2/api"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        # Get home info
        payload = {"method": "Home.getGeneralInfo"}
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("code") != "000000":
            logger.error(f"Failed to get home info: {data}")
            return
        home_id = data["data"]["id"]
        config["home_id"] = home_id
        save_config(config)

        # Get device list
        payload = {"method": "Home.getDeviceList"}
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("code") != "000000":
            logger.error(f"Failed to get device list: {data}")
            return

        for device in data["data"]["devices"]:
            device_id = device["deviceId"]
            existing = get_device_data(device_id) or {}
            logger.debug(f"Device response for {device_id}: {json.dumps(device, indent=2)}")

            # Map battery value if present
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
                "previous_state": existing.get("previous_state", "unknown")  # Preserve previous state
            }
            save_device_data(device_id, device_data)
            logger.info(f"Updated device {device_id} in Redis: {json.dumps(device_data, indent=2)}")

        # Update device mappings
        mappings = get_mappings()
        for device in data["data"]["devices"]:
            device_id = device["deviceId"]
            if not any(m["yolink_device_id"] == device_id for m in mappings["mappings"]):
                mappings["mappings"].append({
                    "yolink_device_id": device_id,
                    "receiver_device_id": "",
                    "door_prop_alarm": False
                })
        save_mappings(mappings)
        logger.info(f"Refreshed {len(data['data']['devices'])} devices and updated mappings")

    except requests.RequestException as e:
        logger.error(f"Failed to refresh devices: {e}")


def get_all_devices():
    """Retrieve all devices from Redis with enhanced logging."""
    try:
        keys = redis_client.keys("device:*")
        devices = [json.loads(redis_client.get(key)) for key in keys]
        logger.debug(f"Retrieved {len(devices)} devices from Redis")
        return devices
    except (redis.RedisError, json.JSONDecodeError) as e:
        logger.error(f"Failed to get all devices: {e}")
        return []


def get_device_data(device_id):
    """Retrieve device data from Redis, returning None if not found."""
    try:
        device_json = redis_client.get(f"device:{device_id}")
        if device_json:
            device = json.loads(device_json)
            logger.debug(f"Retrieved device data for {device_id}: {json.dumps(device, indent=2)}")
            return device
        logger.warning(f"No device data found for {device_id}")
        return None
    except (redis.RedisError, json.JSONDecodeError) as e:
        logger.error(f"Failed to get device data for {device_id}: {e}")
        return None


def save_device_data(device_id, data):
    """Save device data to Redis, preserving previous_state and adding battery mapping."""
    try:
        # Get existing data to preserve previous_state
        existing = get_device_data(device_id) or {}
        if "state" in data and existing.get("state") != data["state"]:
            data["previous_state"] = existing.get("state", "unknown")

        # Ensure battery is mapped if it's an integer
        if "battery" in data and isinstance(data["battery"], int):
            data["battery"] = map_battery_value(data["battery"])

        redis_client.set(f"device:{device_id}", json.dumps(data))
        logger.debug(f"Saved device data for {device_id}: {json.dumps(data, indent=2)}")
    except redis.RedisError as e:
        logger.error(f"Failed to save device data for {device_id}: {e}")