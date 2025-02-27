import paho.mqtt.client as mqtt
import json
import logging
from device_manager import update_device_data
from alerts import trigger_alert
from config import config_data

logger = logging.getLogger()

def on_connect(client, userdata, flags, rc):
    global yolink_mqtt_status
    if rc == 0:
        client.subscribe(userdata['topic'])
        logger.info(f"Subscribed to {userdata['topic']}")
        yolink_mqtt_status['connected'] = True

def on_disconnect(client, userdata, rc):
    global yolink_mqtt_status
    yolink_mqtt_status['connected'] = False

def on_message(client, userdata, msg):
    payload = json.loads(msg.payload.decode())
    device_id = payload.get('deviceId')
    if device_id:
        device_type = parse_device_type(payload.get('event', '').lower(), payload)
        update_device_data(device_id, payload, device_type)
        state = payload['data'].get('state')
        if should_trigger_event(state, device_type):
            trigger_alert(device_id, state, device_type)

def run_mqtt_client():
    home_id = config_data.get('home_id', 'UNKNOWN_HOME_ID')
    mqtt_config = config_data.get('mqtt', {})
    mqtt_client = mqtt.Client(userdata={'topic': mqtt_config['topic'].replace('${Home ID}', home_id)})
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    username = mqtt_config.get('username') or config_data['yolink']['token']
    password = mqtt_config.get('password')
    if username:
        mqtt_client.username_pw_set(username, password)
    try:
        mqtt_client.connect(mqtt_config['url'].replace('mqtt://', ''), mqtt_config['port'])
        mqtt_client.loop_forever()
    except Exception as e:
        logger.error(f"MQTT error: {e}")
        time.sleep(5)
        run_mqtt_client()

def parse_device_type(event_type, payload):
    # Simplified for brevity
    return 'motion' if 'motionsensor' in event_type else None

def should_trigger_event(state, device_type):
    return state == 'alert' and device_type == 'motion'  # Example logic