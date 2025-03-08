"""
Configuration Module - Async Version
===================================

This module handles loading and saving configuration from Redis,
with proper async patterns and error handling.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Import Redis manager
from redis_manager import get_redis

load_dotenv()

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


def get_redis_config() -> dict:
    """
    Retrieve Redis configuration directly from environment variables.

    Returns:
        dict: Redis configuration
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
        use_cache (bool): Whether to use cached config if available
        cache_ttl (int): Cache TTL in seconds

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    global _config_cache, _cache_timestamp

    # Check cache first if enabled
    if use_cache and _config_cache is not None:
        current_time = os.time() if hasattr(os, 'time') else __import__('time').time()
        if current_time - _cache_timestamp < cache_ttl:
            logger.debug("Using cached configuration")
            return _config_cache.copy()

    try:
        redis_client = await get_redis()
        config_json = await redis_client.get("config")

        if config_json:
            config = json.loads(config_json)
            # Ensure all required keys exist
            config.setdefault("supported_timezones", SUPPORTED_TIMEZONES)
            config.setdefault("modbus", DEFAULT_CONFIG["modbus"])
            config.setdefault("redis", DEFAULT_CONFIG["redis"])

            # Update cache
            _config_cache = config.copy()
            _cache_timestamp = os.time() if hasattr(os, 'time') else __import__('time').time()

            return config
        else:
            logger.info("No configuration found in Redis, using defaults")
            await redis_client.set("config", json.dumps(DEFAULT_CONFIG))

            # Update cache
            _config_cache = DEFAULT_CONFIG.copy()
            _cache_timestamp = os.time() if hasattr(os, 'time') else __import__('time').time()

            return DEFAULT_CONFIG.copy()
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()


async def save_config(data: Dict[str, Any]) -> bool:
    """
    Save configuration to Redis asynchronously with error handling.
    Normalizes certain modbus fields if empty.

    Args:
        data (Dict[str, Any]): Configuration data to save

    Returns:
        bool: Success status

    Raises:
        ValueError: If configuration saving fails
    """
    global _config_cache, _cache_timestamp

    try:
        # Normalize data
        data["timezone"] = data.get("timezone", "UTC")
        if "modbus" in data:
            if data["modbus"].get("port") == "":
                data["modbus"]["port"] = 502
            if data["modbus"].get("unit_id") == "":
                data["modbus"]["unit_id"] = 1
            if data["modbus"].get("max_channels") == "":
                data["modbus"]["max_channels"] = 16
            if data["modbus"].get("pulse_seconds") == "":
                data["modbus"]["pulse_seconds"] = 1.0

        # Ensure all required sections exist
        for key in DEFAULT_CONFIG:
            if key not in data:
                data[key] = DEFAULT_CONFIG[key]

        # Add supported timezones if missing
        data.setdefault("supported_timezones", SUPPORTED_TIMEZONES)

        # Save to Redis
        redis_client = await get_redis()
        await redis_client.set("config", json.dumps(data))

        # Update cache
        _config_cache = data.copy()
        _cache_timestamp = os.time() if hasattr(os, 'time') else __import__('time').time()

        logger.info("Configuration saved to Redis")
        return True
    except Exception as e:
        logger.error(f"Error in save_config: {e}")
        raise ValueError(f"Failed to save configuration: {e}")


async def get_user_data(username: str) -> Dict[str, Any]:
    """
    Retrieve user data from Redis asynchronously.

    Args:
        username (str): Username to retrieve data for

    Returns:
        Dict[str, Any]: User data
    """
    try:
        redis_client = await get_redis()
        user_json = await redis_client.get(f"user:{username}")
        return json.loads(user_json) if user_json else {}
    except Exception as e:
        logger.error(f"Error getting user data for {username}: {e}")
        return {}


async def save_user_data(username: str, data: Dict[str, Any]) -> None:
    """
    Save user data to Redis asynchronously.

    Args:
        username (str): Username to save data for
        data (Dict[str, Any]): User data to save
    """
    try:
        redis_client = await get_redis()
        await redis_client.set(f"user:{username}", json.dumps(data))
        logger.debug(f"Saved user data for {username}")
    except Exception as e:
        logger.error(f"Error saving user data for {username}: {e}")


async def clear_config_cache() -> None:
    """
    Clear the configuration cache.
    Call this after making direct changes to Redis.
    """
    global _config_cache, _cache_timestamp
    _config_cache = None
    _cache_timestamp = 0
    logger.debug("Configuration cache cleared")


async def main():
    """Test the async config functions."""
    try:
        # Setup logging
        logging.basicConfig(level=logging.DEBUG)

        # Load configuration
        config = await load_config()
        print("Loaded config:", json.dumps(config, indent=2))

        # Modify and save configuration
        config["test_key"] = "test_value"
        await save_config(config)
        print("Saved config with test_key")

        # Reload and verify
        new_config = await load_config(use_cache=False)
        print("Reload successful:", "test_key" in new_config)

        # Test user data
        await save_user_data("test_user", {"test": "data"})
        user_data = await get_user_data("test_user")
        print("User data:", user_data)

        # Clear cache
        await clear_config_cache()
        print("Cache cleared successfully")

    except Exception as e:
        print(f"Error in main: {e}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())