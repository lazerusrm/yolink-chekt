import os
import yaml
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
config_file = "config.yaml"
config_data = {}
yolink_mqtt_status = {"connected": False}
monitor_mqtt_status = {"connected": False}

# Load or generate encryption key (kept for potential future use, but not used here)
encryption_key_file = "encryption.key"
if os.path.exists(encryption_key_file):
    with open(encryption_key_file, "rb") as f:
        encryption_key = f.read()
else:
    encryption_key = Fernet.generate_key()
    with open(encryption_key_file, "wb") as f:
        f.write(encryption_key)
fernet = Fernet(encryption_key)

def merge_dicts(default: dict, current: dict) -> dict:
    """Recursively merge default dict into current dict."""
    for key, value in default.items():
        if key not in current:
            current[key] = value
        elif isinstance(value, dict) and isinstance(current.get(key), dict):
            current[key] = merge_dicts(value, current[key])
    return current

def get_default_config() -> dict:
    """Return the default configuration structure."""
    return {
        "yolink": {
            "uaid": "",
            "secret_key": "",
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
        "monitor": {"api_key": ""},
        "timezone": "UTC",
        "door_open_timeout": 30,
        "users": {},
        "home_id": ""
    }


def load_config() -> dict:
    global config_data
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as file:
                loaded_data = yaml.safe_load(file)
                config_data = loaded_data if loaded_data is not None else {}
        except Exception as e:
            logger.error(f"Error loading config.yaml: {e}")
            config_data = {}
    else:
        logger.warning("config.yaml not found, initializing with defaults")
        config_data = {}

    # Merge with defaults
    default_config = {
        "yolink": {
            "uaid": "",
            "secret_key": "",
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
        "monitor": {"api_key": ""},
        "timezone": "UTC",
        "door_open_timeout": 30,
        "users": {},
        "home_id": ""
    }

    # Merge defaults into loaded config
    for key, value in default_config.items():
        if key not in config_data:
            config_data[key] = value
        elif isinstance(value, dict) and isinstance(config_data.get(key), dict):
            config_data[key] = {**value, **config_data[key]}

    logger.info(f"Config data loaded: {config_data}")
    return config_data

def save_config(data: dict = None) -> None:
    global config_data
    save_data = data if data is not None else config_data.copy()
    default_config = {
        "yolink": {
            "uaid": "",
            "secret_key": "",
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
        "monitor": {"api_key": ""},
        "timezone": "UTC",
        "door_open_timeout": 30,
        "users": {},
        "home_id": ""
    }
    save_data = {**default_config, **save_data}  # Ensure all keys are present
    try:
        with open(config_file, "w") as file:
            yaml.safe_dump(save_data, file)
        config_data = save_data
        logger.info(f"Config saved: {config_data}")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise