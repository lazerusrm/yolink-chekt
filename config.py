import os
import yaml
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
config_file = "config.yaml"
config_data = {}

# Load or generate encryption key
encryption_key_file = "encryption.key"
if os.path.exists(encryption_key_file):
    with open(encryption_key_file, "rb") as f:
        encryption_key = f.read()
else:
    encryption_key = Fernet.generate_key()
    with open(encryption_key_file, "wb") as f:
        f.write(encryption_key)
fernet = Fernet(encryption_key)


def encrypt_data(data: str) -> str:
    try:
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise


def decrypt_data(encrypted_data: str) -> str:
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise


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
            "url": "",
            "port": 8003,
            "topic": "yl-home/${Home ID}/+/report",
            "username": "",
            "password": ""
        },
        "mqtt_monitor": {
            "url": "",
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
        "users": {}
    }


def load_config() -> dict:
    global config_data
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            loaded_data = yaml.safe_load(file)
            config_data = loaded_data if loaded_data is not None else {}
    else:
        config_data = {}

    # Merge defaults into loaded config
    config_data = merge_dicts(get_default_config(), config_data)

    if "secret_key" in config_data["yolink"] and config_data["yolink"]["secret_key"]:
        try:
            config_data["yolink"]["secret_key"] = decrypt_data(config_data["yolink"]["secret_key"])
        except Exception as e:
            logger.warning(f"Decryption failed for secret_key; resetting to empty: {e}")
            config_data["yolink"]["secret_key"] = ""
    return config_data


def save_config(data: dict = None) -> None:
    global config_data
    save_data = data if data is not None else config_data
    # Ensure full structure before saving
    save_data = merge_dicts(get_default_config(), save_data.copy())
    if "yolink" in save_data and "secret_key" in save_data["yolink"] and save_data["yolink"]["secret_key"]:
        save_data["yolink"]["secret_key"] = encrypt_data(save_data["yolink"]["secret_key"])
    try:
        with open(config_file, "w") as file:
            yaml.safe_dump(save_data, file)
        config_data = save_data
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise