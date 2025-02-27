import requests
import time
from config import load_config, save_config
from db import redis_client

def get_access_token(config):
    if config["yolink"]["token_expiry"] > time.time():
        return config["yolink"]["token"]
    url = "https://api.yosmart.com/open/yolink/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": config["yolink"]["uaid"],
        "client_secret": config["yolink"]["secret_key"]
    }
    response = requests.post(url, data=payload)
    data = response.json()
    config["yolink"]["token"] = data["access_token"]
    config["yolink"]["token_expiry"] = time.time() + data["expires_in"]
    save_config(config)
    return data["access_token"]


def refresh_yolink_devices():
    config = load_config()
    token = get_access_token(config)
    url = "https://api.yosmart.com/open/yolink/v2/api"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"method": "Home.getGeneralInfo"}
    response = requests.post(url, headers=headers, json=payload)
    data = response.json()
    if data.get("code") != "000000":
        logger.error(f"Failed to get home info: {data}")
        return
    home_id = data["data"]["id"]
    config["home_id"] = home_id
    save_config(config)

    payload = {"method": "Home.getDeviceList"}
    response = requests.post(url, headers=headers, json=payload)
    data = response.json()
    if data.get("code") != "000000":
        logger.error(f"Failed to get device list: {data}")
        return
    for device in data["data"]["devices"]:
        device_id = device["deviceId"]
        existing = get_device_data(device_id) or {}
        device_data = {
            "deviceId": device_id,
            "name": device.get("name", f"Device {device_id[-4:]}"),
            "state": existing.get("state", "unknown"),
            "signal": device.get("loraInfo", {}).get("signal", "unknown"),
            "last_seen": existing.get("last_seen", "never"),
            "alarms": existing.get("alarms", {})
        }
        save_device_data(device_id, device_data)

    # Update mappings
    mappings = get_mappings()
    for device in data["data"]["devices"]:
        device_id = device["deviceId"]
        if not any(m["yolink_device_id"] == device_id for m in mappings["mappings"]):
            mappings["mappings"].append({
                "yolink_device_id": device_id,
                "receiver_device_id": ""  # Configurable via /config
            })
    save_mappings(mappings)

def get_all_devices():
    keys = redis_client.keys("device:*")
    return [json.loads(redis_client.get(key)) for key in keys]

def get_device_data(device_id):
    device_json = redis_client.get(f"device:{device_id}")
    return json.loads(device_json) if device_json else None

def save_device_data(device_id, data):
    redis_client.set(f"device:{device_id}", json.dumps(data))