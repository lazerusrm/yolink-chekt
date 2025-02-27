import os
import yaml
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
config_file = "config.yaml"
config_data = {}

# Load or generate encryption key persistently
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
    """Encrypt sensitive data."""
    try:
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise

def load_config() -> dict:
    """Load configuration from file with defaults."""
    global config_data
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            config_data = yaml.safe_load(file) or {}
    else:
        config_data = {}

    # Set default configurations
    config_data.setdefault("yolink", {
        "uaid": "",
        "secret_key": "",
        "token": "",
        "token_expiry": 0
    })
    config_data.setdefault("mqtt", {
        "url": "mqtt://api.yosmart.com",
        "port": 8003,
        "topic": "yl-home/${Home ID}/+/report",
        "username": "",
        "password": ""
    })
    config_data.setdefault("mqtt_monitor", {
        "url": "mqtt://monitor.industrialcamera.com",
        "port": 1883,
        "username": "",
        "password": ""
    })
    config_data.setdefault("receiver_type", "CHEKT")
    config_data.setdefault("chekt", {"api_token": ""})
    config_data.setdefault("sia", {
        "ip": "",
        "port": "",
        "account_id": "",
        "transmitter_id": "",
        "encryption_key": ""
    })
    config_data.setdefault("monitor", {"api_key": ""})
    config_data.setdefault("timezone", "UTC")
    config_data.setdefault("users", {})

    # Decrypt sensitive fields
    if config_data["yolink"].get("secret_key"):
        try:
            config_data["yolink"]["secret_key"] = decrypt_data(config_data["yolink"]["secret_key"])
        except Exception as e:
            logger.warning(f"Could not decrypt secret_key: {e}")
    return config_data

def save_config(data: dict = None) -> None:
    """Save configuration to file with encryption."""
    global config_data
    save_data = data if data is not None else config_data
    encrypted_data = save_data.copy()
    if "yolink" in encrypted_data and "secret_key" in encrypted_data["yolink"]:
        encrypted_data["yolink"]["secret_key"] = encrypt_data(encrypted_data["yolink"]["secret_key"])
    try:
        with open(config_file, "w") as file:
            yaml.safe_dump(encrypted_data, file)
        config_data = save_data
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise