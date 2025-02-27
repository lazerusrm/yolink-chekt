import json
import logging
from db import redis_client
from utils import load_yaml
from monitor_mqtt import trigger_monitor_event
from mappings import get_mappings

logger = logging.getLogger()

def load_devices_to_redis():
    devices_data = load_yaml('devices.yaml')
    home_id = devices_data.get('homes', {}).get('id', 'UNKNOWN_HOME_ID')
    redis_client.set('home_id', home_id)
    for device in devices_data.get('devices', []):
        redis_client.set(f"device:{device['deviceId']}", json.dumps(device))

def get_device_data(device_id):
    device_json = redis_client.get(f"device:{device_id}")
    return json.loads(device_json) if device_json else None

def get_all_devices():
    keys = redis_client.keys('device:*')
    devices = [json.loads(redis_client.get(key)) for key in keys]
    mappings = get_mappings().get('mappings', {})
    device_mappings = {m['yolink_device_id']: m for m in mappings}
    for device in devices:
        device_id = device['deviceId']
        mapping = device_mappings.get(device_id, {})
        device['chekt_zone'] = mapping.get('chekt_zone', 'N/A')
    return devices

def update_device_data(device_id, payload, device_type=None):
    device = get_device_data(device_id)
    if not device:
        logger.warning(f"Device {device_id} not found.")
        return
    device['state'] = payload['data'].get('state', device.get('state', 'unknown'))
    redis_client.set(f"device:{device_id}", json.dumps(device))
    monitor_data = {
        "home_id": redis_client.get('home_id').decode(),
        "device_id": device_id,
        "device_type": device_type,
        "sensor_data": {
            "state": device.get('state'),
            "alarms": device.get('alarm', {}),
            "water_depth": payload['data'].get('waterDepth')
        }
    }
    trigger_monitor_event(device_id, "Device Data Updated", monitor_data)