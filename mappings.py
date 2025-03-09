"""
Device Mappings Module - Async Version
======================================

This module manages mappings between YoLink devices and receivers (CHEKT zones, 
SIA zones, Modbus relay channels).
"""

import json
import logging
from typing import Dict, Any, Optional, Union, List

# Import Redis manager
from redis_manager import get_redis

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Mappings cache to reduce Redis lookups
_mappings_cache: Optional[Dict[str, Any]] = None
_cache_timestamp: float = 0


async def get_mappings(use_cache: bool = True, cache_ttl: int = 5) -> Dict[str, Any]:
    """
    Retrieve all mappings from Redis asynchronously with caching.

    Args:
        use_cache (bool): Whether to use cached mappings if available
        cache_ttl (int): Cache TTL in seconds

    Returns:
        Dict[str, Any]: Mappings dictionary with structure {mappings: [...]}
    """
    global _mappings_cache, _cache_timestamp

    # Use cache if available and enabled
    if use_cache and _mappings_cache is not None:
        current_time = __import__('time').time()
        if current_time - _cache_timestamp < cache_ttl:
            logger.debug("Using cached mappings")
            return _mappings_cache.copy()

    try:
        redis_client = await get_redis()
        mappings_json = await redis_client.get("mappings")

        if mappings_json:
            mappings = json.loads(mappings_json)
            # Update cache
            _mappings_cache = mappings.copy()
            _cache_timestamp = __import__('time').time()
            return mappings
        else:
            # Initialize empty mappings
            default_mappings = {"mappings": []}
            _mappings_cache = default_mappings.copy()
            _cache_timestamp = __import__('time').time()
            return default_mappings
    except Exception as e:
        logger.error(f"Error retrieving mappings: {e}")
        return {"mappings": []}


async def save_mappings(mappings: Dict[str, Any]) -> bool:
    """
    Save all mappings to Redis asynchronously.

    Args:
        mappings (Dict[str, Any]): Mappings to save

    Returns:
        bool: Success status
    """
    global _mappings_cache, _cache_timestamp

    try:
        if not isinstance(mappings, dict) or "mappings" not in mappings:
            logger.error("Invalid mappings format, expected {mappings: [...]}")
            return False

        # Normalize mappings to ensure consistent structure
        normalized_mappings = {"mappings": []}

        for mapping in mappings.get("mappings", []):
            if not isinstance(mapping, dict) or "yolink_device_id" not in mapping:
                logger.warning(f"Skipping invalid mapping entry: {mapping}")
                continue

            # Create normalized mapping with default values
            normalized_mapping = {
                "yolink_device_id": mapping["yolink_device_id"],
                "chekt_zone": mapping.get("chekt_zone", "N/A"),
                "sia_zone": mapping.get("sia_zone", "N/A"),
                "relay_channel": mapping.get("relay_channel", "N/A"),
                "door_prop_alarm": mapping.get("door_prop_alarm", False),
                "use_relay": mapping.get("use_relay", False)
            }

            normalized_mappings["mappings"].append(normalized_mapping)

        # Save to Redis
        redis_client = await get_redis()
        await redis_client.set("mappings", json.dumps(normalized_mappings))

        # Update cache
        _mappings_cache = normalized_mappings.copy()
        _cache_timestamp = __import__('time').time()

        logger.debug(f"Saved {len(normalized_mappings['mappings'])} mappings to Redis")
        return True
    except Exception as e:
        logger.error(f"Error saving mappings: {e}")
        return False


async def get_mapping(yolink_device_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a specific mapping by YoLink device ID asynchronously.

    Args:
        yolink_device_id (str): Device ID to get mapping for

    Returns:
        Optional[Dict[str, Any]]: Mapping for the device or None if not found
    """
    mappings = await get_mappings()
    for mapping in mappings.get("mappings", []):
        if mapping.get("yolink_device_id") == yolink_device_id:
            return mapping
    return None


async def save_mapping(device_id: str, chekt_zone: str = None, sia_zone: str = None,
                       relay_channel: str = None, use_relay: bool = None,
                       door_prop_alarm: bool = None) -> bool:
    """
    Save a mapping for a specific device ID asynchronously.
    If relay_channel is set and not 'N/A', automatically set use_relay to True.

    Args:
        device_id (str): YoLink device ID
        chekt_zone (str, optional): CHEKT zone to map to
        sia_zone (str, optional): SIA zone to map to
        relay_channel (str, optional): Relay channel to map to
        use_relay (bool, optional): Whether to use relay
        door_prop_alarm (bool, optional): Whether door prop alarm is enabled

    Returns:
        bool: Success status
    """
    try:
        # Get all mappings
        mappings = await get_mappings()
        found = False

        # If relay_channel is provided and valid, automatically set use_relay to True
        if relay_channel is not None and relay_channel != 'N/A' and relay_channel.strip():
            use_relay = True
            logger.info(f"Valid relay channel provided for device {device_id}, setting use_relay to True automatically")

        # Find and update existing mapping
        for mapping in mappings.get("mappings", []):
            if mapping.get("yolink_device_id") == device_id:
                # Log previous and new values
                if chekt_zone is not None:
                    logger.debug(f"Updating CHEKT zone for device {device_id}: {mapping.get('chekt_zone', 'N/A')} -> {chekt_zone}")
                    mapping["chekt_zone"] = chekt_zone
                if sia_zone is not None:
                    logger.debug(f"Updating SIA zone for device {device_id}: {mapping.get('sia_zone', 'N/A')} -> {sia_zone}")
                    mapping["sia_zone"] = sia_zone
                if relay_channel is not None:
                    logger.debug(f"Updating relay channel for device {device_id}: {mapping.get('relay_channel', 'N/A')} -> {relay_channel}")
                    mapping["relay_channel"] = relay_channel
                if use_relay is not None:
                    logger.debug(f"Updating use_relay for device {device_id}: {mapping.get('use_relay', False)} -> {use_relay}")
                    mapping["use_relay"] = use_relay
                if door_prop_alarm is not None:
                    logger.debug(f"Updating door_prop_alarm for device {device_id}: {mapping.get('door_prop_alarm', False)} -> {door_prop_alarm}")
                    mapping["door_prop_alarm"] = door_prop_alarm
                found = True
                break

        # Create new mapping if not found
        if not found:
            logger.info(f"Creating new mapping for device {device_id}")
            new_mapping = {"yolink_device_id": device_id}
            if chekt_zone is not None:
                new_mapping["chekt_zone"] = chekt_zone
            else:
                new_mapping["chekt_zone"] = "N/A"

            if sia_zone is not None:
                new_mapping["sia_zone"] = sia_zone
            else:
                new_mapping["sia_zone"] = "N/A"

            if relay_channel is not None:
                new_mapping["relay_channel"] = relay_channel
            else:
                new_mapping["relay_channel"] = "N/A"

            new_mapping["use_relay"] = use_relay if use_relay is not None else False
            new_mapping["door_prop_alarm"] = door_prop_alarm if door_prop_alarm is not None else False

            logger.debug(f"New mapping data: {new_mapping}")
            mappings.setdefault("mappings", []).append(new_mapping)

        # Save all mappings
        success = await save_mappings(mappings)
        if success:
            logger.debug(f"Successfully saved mapping for device {device_id}")
            # Clear cache to ensure future get_mapping calls retrieve updated data
            await clear_cache()
            logger.debug("Cleared mappings cache after saving")
        return success
    except Exception as e:
        logger.error(f"Error saving mapping for device {device_id}: {e}")
        return False


async def delete_mapping(device_id: str) -> bool:
    """
    Delete a mapping for a specific device ID.

    Args:
        device_id (str): Device ID to delete mapping for

    Returns:
        bool: True if mapping was deleted, False otherwise
    """
    try:
        mappings = await get_mappings()
        original_count = len(mappings.get("mappings", []))

        # Filter out the mapping for the specified device
        mappings["mappings"] = [
            m for m in mappings.get("mappings", [])
            if m.get("yolink_device_id") != device_id
        ]

        # If a mapping was removed, save the updated mappings
        if len(mappings.get("mappings", [])) < original_count:
            success = await save_mappings(mappings)
            if success:
                logger.info(f"Deleted mapping for device {device_id}")
            return success
        else:
            logger.warning(f"No mapping found for device {device_id}")
            return False
    except Exception as e:
        logger.error(f"Error deleting mapping for device {device_id}: {e}")
        return False


async def get_devices_by_chekt_zone(zone: str) -> List[str]:
    """
    Get all device IDs mapped to a specific CHEKT zone.

    Args:
        zone (str): CHEKT zone to search for

    Returns:
        List[str]: List of device IDs
    """
    try:
        mappings = await get_mappings()
        devices = [
            m.get("yolink_device_id") for m in mappings.get("mappings", [])
            if m.get("chekt_zone") == zone
        ]
        return devices
    except Exception as e:
        logger.error(f"Error getting devices for CHEKT zone {zone}: {e}")
        return []


async def get_devices_by_relay_channel(channel: Union[str, int]) -> List[str]:
    """
    Get all device IDs mapped to a specific relay channel.

    Args:
        channel (Union[str, int]): Relay channel to search for

    Returns:
        List[str]: List of device IDs
    """
    try:
        # Convert channel to string for comparison
        channel_str = str(channel)

        mappings = await get_mappings()
        devices = [
            m.get("yolink_device_id") for m in mappings.get("mappings", [])
            if m.get("relay_channel") == channel_str and m.get("use_relay", False)
        ]
        return devices
    except Exception as e:
        logger.error(f"Error getting devices for relay channel {channel}: {e}")
        return []


async def clear_cache() -> None:
    """
    Clear the mappings cache.
    Call this after making direct changes to Redis.
    """
    global _mappings_cache, _cache_timestamp
    _mappings_cache = None
    _cache_timestamp = 0
    logger.debug("Mappings cache cleared")


# Example usage
async def main():
    """Test the async mapping functions."""
    import asyncio

    # Setup logging
    logging.basicConfig(level=logging.DEBUG)

    try:
        # Test saving a mapping
        await save_mapping(
            "test_device",
            chekt_zone="Zone1",
            relay_channel="1",
            use_relay=True,
            door_prop_alarm=True
        )

        # Get all mappings
        mappings = await get_mappings()
        print("Mappings:", json.dumps(mappings, indent=2))

        # Get a specific mapping
        mapping = await get_mapping("test_device")
        print("Mapping for test_device:", json.dumps(mapping, indent=2))

        # Test finding devices by zone
        devices_in_zone1 = await get_devices_by_chekt_zone("Zone1")
        print("Devices in Zone1:", devices_in_zone1)

        # Test finding devices by relay channel
        devices_on_channel1 = await get_devices_by_relay_channel(1)
        print("Devices on channel 1:", devices_on_channel1)

        # Clear cache
        await clear_cache()
        print("Cache cleared")

        # Test deleting a mapping
        delete_success = await delete_mapping("test_device")
        print(f"Delete mapping success: {delete_success}")

    except Exception as e:
        print(f"Error in main: {e}")


if __name__ == "__main__":
    asyncio.run(main())