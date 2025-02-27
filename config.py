import os
import yaml
import logging

logger = logging.getLogger()
config_file = "config.yaml"
config_data = {}

def load_config():
    global config_data
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            config_data = yaml.safe_load(file) or {}
    if 'mqtt' not in config_data:
        config_data['mqtt'] = {
            'url': 'mqtt://api.yosmart.com',
            'port': 8003,
            'topic': 'yl-home/${Home ID}/+/report',
            'username': '',
            'password': ''
        }
    if 'mqtt_monitor' not in config_data:
        config_data['mqtt_monitor'] = {
            'url': 'mqtt://monitor.industrialcamera.com',
            'port': 1883,
            'username': '',
            'password': ''
        }
    return config_data