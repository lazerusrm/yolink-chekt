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


def save_mapping(yolink_device_id, chekt_zone=None, relay_channel=None, use_relay=False):
    """
    Save mapping for a device.

    Args:
        yolink_device_id: The device ID to save mapping for
        chekt_zone: Optional CHEKT zone to assign
        relay_channel: Optional relay channel to assign
        use_relay: Whether to use relay for this device (can use both CHEKT and relay)
    """
    mappings = get_mappings()
    mappings_list = mappings["mappings"]
    existing = next((m for m in mappings_list if m["yolink_device_id"] == yolink_device_id), None)

    if existing:
        # Update existing mapping
        if chekt_zone is not None:
            existing["chekt_zone"] = chekt_zone
        if relay_channel is not None:
            existing["relay_channel"] = relay_channel
        if use_relay is not None:
            existing["use_relay"] = use_relay
    else:
        # Create new mapping with default values
        new_mapping = {
            "yolink_device_id": yolink_device_id,
            "chekt_zone": chekt_zone if chekt_zone is not None else "N/A",
            "door_prop_alarm": False,
            "receiver_device_id": "",  # Keep for compatibility if needed
            "relay_channel": relay_channel if relay_channel is not None else "N/A",
            "use_relay": use_relay if use_relay is not None else False
        }
        mappings_list.append(new_mapping)

    mappings["mappings"] = mappings_list
    save_mappings(mappings)

    return True