import json
from db import redis_client


def get_mappings():
    mappings_json = redis_client.get("mappings")
    return json.loads(mappings_json) if mappings_json else {"mappings": []}


def save_mappings(mappings):
    redis_client.set("mappings", json.dumps(mappings))


def get_mapping(yolink_device_id):
    mappings = get_mappings()["mappings"]
    return next((m for m in mappings if m["yolink_device_id"] == yolink_device_id), None)


def save_mapping(device_id, chekt_zone=None, relay_channel=None, use_relay=None):
    """
    Save a mapping for a specific device ID.
    If relay_channel is set and not 'N/A', automatically set use_relay to True
    """
    try:
        mappings = get_mappings()
        found = False

        # If relay_channel is provided and valid, automatically set use_relay to True
        if relay_channel is not None and relay_channel != 'N/A' and relay_channel.strip():
            use_relay = True

        for mapping in mappings["mappings"]:
            if mapping["yolink_device_id"] == device_id:
                if chekt_zone is not None:
                    mapping["chekt_zone"] = chekt_zone
                if relay_channel is not None:
                    mapping["relay_channel"] = relay_channel
                if use_relay is not None:
                    mapping["use_relay"] = use_relay
                found = True
                break

        if not found:
            new_mapping = {"yolink_device_id": device_id}
            if chekt_zone is not None:
                new_mapping["chekt_zone"] = chekt_zone
            if relay_channel is not None:
                new_mapping["relay_channel"] = relay_channel
            if use_relay is not None:
                new_mapping["use_relay"] = use_relay
            mappings["mappings"].append(new_mapping)

        save_mappings(mappings)
        logger.debug(f"Successfully saved mapping for device {device_id}")
        return True
    except Exception as e:
        logger.error(f"Error saving mapping for device {device_id}: {e}")
        return False