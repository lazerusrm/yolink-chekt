import os
import json
from dotenv import load_dotenv
from db import redis_client

load_dotenv()

# List of supported North American timezones
SUPPORTED_TIMEZONES = [
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Anchorage",
    "America/Honolulu",
    "America/Phoenix",
    "America/Detroit",
    "America/Indiana/Indianapolis",
    "America/Boise",
    "America/Juneau",
    "America/Nome",
    "America/Adak",
    "Pacific/Honolulu",
    "America/Mexico_City",
    "America/Tijuana",
    "America/Toronto",
    "America/Halifax",
    "America/St_Johns",
    "America/Puerto_Rico",
]

DEFAULT_CONFIG = {
    "yolink": {
        "uaid": os.getenv("YOLINK_UAID", ""),
        "secret_key": os.getenv("YOLINK_SECRET_KEY", ""),
        "token": "",
        "token_expiry": 0
    },
    "mqtt": {
        "url": "mqtt://api.yosmart.com",
        "port": 8003,
        "topic": "yl-home/${Home ID}/+/report"
    },
    "mqtt_monitor": {
        "url": "mqtt://monitor.industrialcamera.com",
        "port": 1883,
        "username": "",
        "password": "",
        "client_id": "monitor_client_id"
    },
    "receiver_type": "CHEKT",
    "chekt": {
        "api_token": "",
        "ip": "",
        "port": 30003
    },
    "sia": {
        "ip": "",
        "port": "",
        "account_id": "",
        "transmitter_id": "",
        "encryption_key": ""
    },
    "modbus": {
        "ip": "",
        "port": 502,  # Default Modbus TCP port
        "unit_id": 1,  # Default Modbus device ID/slave address
        "max_channels": 16,  # Default to 16 channels (supports 8 or 16)
        "pulse_seconds": 1,  # Default pulse duration in seconds
        "enabled": False  # Whether Modbus relay is enabled
    },
    "monitor": {"api_key": os.getenv("MONITOR_API_KEY", "")},
    "timezone": "UTC",
    "door_open_timeout": 30,
    "home_id": "",
    "supported_timezones": SUPPORTED_TIMEZONES  # Added for frontend use
}


def load_config():
    """Load configuration from Redis, or set and return default if none exists."""
    config_json = redis_client.get("config")
    if config_json:
        config = json.loads(config_json)
        # Ensure supported_timezones is always present
        config["supported_timezones"] = SUPPORTED_TIMEZONES

        # Ensure modbus configuration is present (for backward compatibility)
        if "modbus" not in config:
            config["modbus"] = DEFAULT_CONFIG["modbus"]

        return config
    else:
        redis_client.set("config", json.dumps(DEFAULT_CONFIG))
        return DEFAULT_CONFIG


def save_config(data):
    """Save configuration to Redis after validating timezone."""
    if "timezone" in data and data["timezone"] not in SUPPORTED_TIMEZONES:
        raise ValueError(f"Invalid timezone: {data['timezone']}")
    redis_client.set("config", json.dumps(data))


def get_user_data(username):
    """Retrieve user data from Redis."""
    user_json = redis_client.get(f"user:{username}")
    return json.loads(user_json) if user_json else {}


def save_user_data(username, data):
    """Save user data to Redis."""
    redis_client.set(f"user:{username}", json.dumps(data))