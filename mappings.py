import json
from db import redis_client
from utils import load_yaml, save_to_yaml

def load_mappings_to_redis():
    mappings_data = load_yaml('mappings.yaml')
    redis_client.set('mappings', json.dumps(mappings_data))

def get_mappings():
    mappings_json = redis_client.get('mappings')
    return json.loads(mappings_json) if mappings_json else {"mappings": []}

def get_mapping(device_id):
    mappings = get_mappings().get('mappings', [])
    return next((m for m in mappings if m['yolink_device_id'] == device_id), None)