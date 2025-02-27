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

def save_mapping(yolink_device_id, receiver_device_id):
    mappings = get_mappings()
    mappings_list = mappings["mappings"]
    existing = next((m for m in mappings_list if m["yolink_device_id"] == yolink_device_id), None)
    if existing:
        existing["receiver_device_id"] = receiver_device_id
    else:
        mappings_list.append({"yolink_device_id": yolink_device_id, "receiver_device_id": receiver_device_id})
    mappings["mappings"] = mappings_list
    save_mappings(mappings)