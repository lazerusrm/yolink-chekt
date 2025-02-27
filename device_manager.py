import requests
import time
import json
import logging
from config import load_config, save_config
from db import redis_client
from mappings import get_mappings, save_mappings  # Added missing imports

logger = logging.getLogger(__name__)

def get_access_token(config):
    if config["yolink"]["token_expiry"] > time.time():
        return config["yolink"]["token"]
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
        config["yolink"]["token"] = data["access_token"]
        config["yolink"]["token_expiry"] = time.time() + data["expires_in"]
        save_config(config)
        return data["access_token"]
    except requests.RequestException as e:
        logger.error(f"Failed to get access token: {e}")
        return None

def refresh_yolink_devices():
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
            # Extract battery and signal, with fallbacks to existing data
            battery = device.get("battery", existing.get("battery", "unknown"))
            signal = device.get("loraInfo", {}).get("signal", existing.get("signal", "unknown"))

            device_data = {
                "deviceId": device_id,
                "name": device.get("name", f"Device {device_id[-4:]}"),
                "type": device.get("type", "unknown"),
                "state": existing.get("state", "unknown"),
                "signal": signal,
                "battery": battery,
                "last_seen": existing.get("last_seen", "never"),
                "alarms": existing.get("alarms", {}),
                "temperature": device.get("temperature", existing.get("temperature", "unknown")),
                "humidity": device.get("humidity", existing.get("humidity", "unknown")),
            }
            save_device_data(device_id, device_data)

    except requests.RequestException as e:
        logger.error(f"Failed to refresh devices: {e}")

def get_all_devices():
    try:
        keys = redis_client.keys("device:*")
        return [json.loads(redis_client.get(key)) for key in keys]
    except (redis.RedisError, json.JSONDecodeError) as e:
        logger.error(f"Failed to get all devices: {e}")
        return []

def get_device_data(device_id):
    try:
        device_json = redis_client.get(f"device:{device_id}")
        return json.loads(device_json) if device_json else None
    except (redis.RedisError, json.JSONDecodeError) as e:
        logger.error(f"Failed to get device data for {device_id}: {e}")
        return None

def save_device_data(device_id, data):
    try:
        redis_client.set(f"device:{device_id}", json.dumps(data))
    except redis.RedisError as e:
        logger.error(f"Failed to save device data for {device_id}: {e}")