import paho.mqtt.client as mqtt
import json
from datetime import datetime
import logging
from config import config_data, monitor_mqtt_status  # Updated import

logger = logging.getLogger(__name__)
monitor_mqtt_client = None

def initialize_monitor_mqtt_client():
    global monitor_mqtt_client
    mqtt_config = config_data.get('mqtt_monitor', {})
    if not mqtt_config.get('url'):
        logger.warning("Monitor MQTT URL not configured; skipping initialization.")
        return
    monitor_mqtt_client = mqtt.Client(mqtt_config.get('client_id', 'monitor_client_id'))
    monitor_mqtt_client.on_connect = on_monitor_mqtt_connect
    monitor_mqtt_client.on_message = on_monitor_mqtt_message
    monitor_mqtt_client.on_disconnect = on_monitor_mqtt_disconnect
    if mqtt_config.get('username') and mqtt_config.get('password'):
        monitor_mqtt_client.username_pw_set(mqtt_config['username'], mqtt_config['password'])
    try:
        monitor_mqtt_client.connect(mqtt_config['url'].replace('mqtt://', ''), mqtt_config.get('port', 1883))
        monitor_mqtt_client.loop_start()
    except Exception as e:
        logger.error(f"Monitor MQTT error: {e}")

def on_monitor_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe('monitor/commands')
        logger.info("Connected to monitor MQTT")
        monitor_mqtt_status['connected'] = True
    else:
        logger.error(f"Monitor MQTT connection failed with code {rc}")

def on_monitor_mqtt_disconnect(client, userdata, rc):
    monitor_mqtt_status['connected'] = False
    logger.warning("Monitor MQTT disconnected")

def on_monitor_mqtt_message(client, userdata, msg):
    logger.info(f"Monitor message: {msg.payload.decode()}")

def publish_to_monitor(topic, payload):
    if monitor_mqtt_client and monitor_mqtt_status['connected']:
        monitor_mqtt_client.publish(f"monitor/{topic}", json.dumps(payload))
    else:
        logger.warning("Cannot publish to monitor MQTT; client not connected")

def trigger_monitor_event(device_id, event_description, data=None):
    payload = {'device_id': device_id, 'event_description': event_description, 'timestamp': datetime.utcnow().isoformat() + 'Z'}
    if data:
        payload.update(data)
    publish_to_monitor('events', payload)

if __name__ == "__main__":
    initialize_monitor_mqtt_client()