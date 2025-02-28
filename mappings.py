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

def save_mapping(yolink_device_id, chekt_zone):
    mappings = get_mappings()
    mappings_list = mappings["mappings"]
    existing = next((m for m in mappings_list if m["yolink_device_id"] == yolink_device_id), None)
    if existing:
        existing["chekt_zone"] = chekt_zone
    else:
        mappings_list.append({
            "yolink_device_id": yolink_device_id,
            "chekt_zone": chekt_zone,
            "door_prop_alarm": False,
            "receiver_device_id": ""  # Keep for compatibility if needed
        })
    mappings["mappings"] = mappings_list
    save_mappings(mappings)