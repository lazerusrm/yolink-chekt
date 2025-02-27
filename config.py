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


def ensure_config_defaults(config: dict) -> dict:
    """Ensure config_data has all required keys with defaults."""
    config.setdefault("yolink", {
        "uaid": "",
        "secret_key": "",
        "token": "",
        "token_expiry": 0
    })
    config.setdefault("mqtt", {
        "url": "",
        "port": 8003,
        "topic": "yl-home/${Home ID}/+/report",
        "username": "",
        "password": ""
    })
    config.setdefault("mqtt_monitor", {
        "url": "",
        "port": 1883,
        "username": "",
        "password": "",
        "client_id": "monitor_client_id"
    })
    config.setdefault("receiver_type", "CHEKT")
    config.setdefault("chekt", {
        "api_token": "",
        "ip": "",
        "port": 30003
    })
    config.setdefault("sia", {
        "ip": "",
        "port": "",
        "account_id": "",
        "transmitter_id": "",
        "encryption_key": ""
    })
    config.setdefault("monitor", {"api_key": ""})
    config.setdefault("timezone", "UTC")
    config.setdefault("door_open_timeout", 30)
    config.setdefault("users", {})
    return config


def load_config() -> dict:
    global config_data
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            loaded_data = yaml.safe_load(file)
            config_data = loaded_data if loaded_data is not None else {}
    else:
        config_data = {}

    config_data = ensure_config_defaults(config_data)

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
    save_data = ensure_config_defaults(save_data.copy())  # Ensure defaults before saving
    if "yolink" in save_data and "secret_key" in save_data["yolink"] and save_data["yolink"]["secret_key"]:
        save_data["yolink"]["secret_key"] = encrypt_data(save_data["yolink"]["secret_key"])
    try:
        with open(config_file, "w") as file:
            yaml.safe_dump(save_data, file)
        config_data = save_data  # Update global config_data
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise