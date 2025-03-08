"""
Configuration Module - Async Version (Enhanced)
===============================================

Handles loading and saving configuration and user data from Redis with async patterns,
caching, and robust error handling for the Yolink to CHEKT integration.
"""

import os
import json
import logging
import time
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Import Redis manager
from .redis_manager import get_redis

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# Default configuration with environment variable fallbacks
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
        "port": 30003,
        "enabled": True
    },
    "sia": {
        "ip": "",
        "port": "",
        "account_id": "",
        "transmitter_id": "",
        "encryption_key": "",
        "enabled": False
    },
    "modbus": {
        "ip": "",
        "port": 502,
        "unit_id": 1,
        "max_channels": 16,
        "pulse_seconds": 1.0,
        "enabled": False,
        "follower_mode": False
    },
    "monitor": {"api_key": os.getenv("MONITOR_API_KEY", "")},
    "redis": {
        "host": os.getenv("REDIS_HOST", "redis"),
        "port": int(os.getenv("REDIS_PORT", 6379)),
        "db": 0
    },
    "timezone": "UTC",
    "door_open_timeout": 30,
    "home_id": "",
    "supported_timezones": SUPPORTED_TIMEZONES
}

# Configuration cache
_config_cache: Optional[Dict[str, Any]] = None
_cache_timestamp: float = 0

def get_redis_config() -> Dict[str, Any]:
    """
    Retrieve Redis configuration directly from environment variables.

    Returns:
        Dict[str, Any]: Redis configuration dictionary
    """
    return {
        "host": os.getenv("REDIS_HOST", "redis"),
        "port": int(os.getenv("REDIS_PORT", 6379)),
        "db": 0
    }

async def load_config(use_cache: bool = True, cache_ttl: int = 5) -> Dict[str, Any]:
    """
    Load configuration from Redis asynchronously with caching.
    If no config is stored, save and return the default configuration.

    Args:
        use_cache (bool): Whether to use cached config if available (default: True)
        cache_ttl (int): Cache TTL in seconds (default: 5)

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    global _config_cache, _cache_timestamp

    if use_cache and _config_cache is not None:
        current_time = time.time()
        if current_time - _cache_timestamp < cache_ttl:
            logger.debug("Returning cached configuration")
            return _config_cache.copy()

    try:
        redis_client = await get_redis()
        config_json = await redis_client.get("config")
        if config_json:
            config = json.loads(config_json)
            # Ensure all required keys exist
            for key in DEFAULT_CONFIG:
                config.setdefault(key, DEFAULT_CONFIG[key])
            # Update nested defaults if necessary
            config["supported_timezones"] = SUPPORTED_TIMEZONES
            _config_cache = config.copy()
            _cache_timestamp = time.time()
            logger.debug("Loaded configuration from Redis")
            return config
        else:
            logger.info("No configuration found in Redis, initializing with defaults")
            await redis_client.set("config", json.dumps(DEFAULT_CONFIG))
            _config_cache = DEFAULT_CONFIG.copy()
            _cache_timestamp = time.time()
            return DEFAULT_CONFIG.copy()
    except Exception as e:
        logger.error(f"Error loading config from Redis: {e}")
        return DEFAULT_CONFIG.copy()

async def save_config(data: Dict[str, Any]) -> bool:
    """
    Save configuration to Redis asynchronously with normalization.

    Args:
        data (Dict[str, Any]): Configuration data to save

    Returns:
        bool: True if successful, False otherwise
    """
    global _config_cache, _cache_timestamp

    try:
        # Normalize data
        normalized_data = data.copy()
        normalized_data["timezone"] = normalized_data.get("timezone", "UTC")
        if "modbus" in normalized_data:
            modbus = normalized_data["modbus"]
            modbus["port"] = int(modbus.get("port") or 502)
            modbus["unit_id"] = int(modbus.get("unit_id") or 1)
            modbus["max_channels"] = int(modbus.get("max_channels") or 16)
            modbus["pulse_seconds"] = float(modbus.get("pulse_seconds") or 1.0)

        # Ensure all required sections exist
        for key in DEFAULT_CONFIG:
            normalized_data.setdefault(key, DEFAULT_CONFIG[key])
        normalized_data["supported_timezones"] = SUPPORTED_TIMEZONES

        redis_client = await get_redis()
        await redis_client.set("config", json.dumps(normalized_data))
        _config_cache = normalized_data.copy()
        _cache_timestamp = time.time()
        logger.info("Configuration saved to Redis")
        return True
    except Exception as e:
        logger.error(f"Error saving config to Redis: {e}")
        return False

async def get_user_data(username: str) -> Dict[str, Any]:
    """
    Retrieve user data from Redis asynchronously.

    Args:
        username (str): Username to retrieve data for

    Returns:
        Dict[str, Any]: User data, empty dict if not found or on error
    """
    try:
        redis_client = await get_redis()
        user_json = await redis_client.get(f"user:{username}")
        return json.loads(user_json) if user_json else {}
    except Exception as e:
        logger.error(f"Error retrieving user data for {username}: {e}")
        return {}

async def save_user_data(username: str, data: Dict[str, Any]) -> bool:
    """
    Save user data to Redis asynchronously.

    Args:
        username (str): Username to save data for
        data (Dict[str, Any]): User data to save

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        redis_client = await get_redis()
        await redis_client.set(f"user:{username}", json.dumps(data))
        logger.debug(f"Saved user data for {username}")
        return True
    except Exception as e:
        logger.error(f"Error saving user data for {username}: {e}")
        return False

async def clear_config_cache() -> None:
    """
    Clear the configuration cache.
    Use after direct Redis modifications outside this module.
    """
    global _config_cache, _cache_timestamp
    _config_cache = None
    _cache_timestamp = 0
    logger.debug("Configuration cache cleared")

if __name__ == "__main__":
    async def test_config():
        """Test the configuration module standalone."""
        logging.basicConfig(level=logging.DEBUG)
        config = await load_config()
        print("Initial Config:", json.dumps(config, indent=2))
        config["test_key"] = "test_value"
        success = await save_config(config)
        print(f"Save Config: {'Success' if success else 'Failed'}")
        updated_config = await load_config(use_cache=False)
        print("Updated Config:", json.dumps(updated_config, indent=2))
        await save_user_data("test_user", {"password": "test", "force_password_change": True})
        user_data = await get_user_data("test_user")
        print("User Data:", user_data)
        await clear_config_cache()
        print("Cache cleared")

    import asyncio
    asyncio.run(test_config())