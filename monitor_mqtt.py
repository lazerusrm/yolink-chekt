import paho.mqtt.client as mqtt
import json
from datetime import datetime
import logging
from config import config_data

logger = logging.getLogger()
monitor_mqtt_client = None

def initialize_monitor_mqtt_client():
    global monitor_mqtt_client
    mqtt_config = config_data.get('mqtt_monitor', {})
    monitor_mqtt_client = mqtt.Client(mqtt_config.get('client_id', 'monitor_client_id'))
    monitor_mqtt_client.on_connect = on_monitor_mqtt_connect
    monitor_mqtt_client.on_message = on_monitor_mqtt_message
    if mqtt_config.get('username'):
        monitor_mqtt_client.username_pw_set(mqtt_config['username'], mqtt_config['password'])
    try:
        monitor_mqtt_client.connect(mqtt_config['url'].replace('mqtt://', ''), mqtt_config['port'])
        monitor_mqtt_client.loop_start()
    except Exception as e:
        logger.error(f"Monitor MQTT error: {e}")

def on_monitor_mqtt_connect(client, userdata, flags, rc):
    global monitor_mqtt_status
    if rc == 0:
        client.subscribe('monitor/commands')
        logger.info("Connected to monitor MQTT")
        monitor_mqtt_status['connected'] = True

def on_monitor_mqtt_disconnect(client, userdata, rc):
    global monitor_mqtt_status
    monitor_mqtt_status['connected'] = False

def on_monitor_mqtt_message(client, userdata, msg):
    logger.info(f"Monitor message: {msg.payload.decode()}")

def publish_to_monitor(topic, payload):
    if monitor_mqtt_client:
        monitor_mqtt_client.publish(f"monitor/{topic}", json.dumps(payload))

def trigger_monitor_event(device_id, event_description, data=None):
    payload = {'device_id': device_id, 'event_description': event_description, 'timestamp': datetime.utcnow().isoformat() + 'Z'}
    if data:
        payload.update(data)
    publish_to_monitor('events', payload)