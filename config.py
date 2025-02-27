import os
import json
from dotenv import load_dotenv
from db import redis_client

load_dotenv()

DEFAULT_CONFIG = {
    "yolink": {
        "uaid": os.getenv("YOLINK_UAID", ""),
        "secret_key": os.getenv("YOLINK_SECRET_KEY", ""),
        "token": "",
        "token_expiry": 0
    },
    "mqtt": {
        "url": "mqtt://api.yosmart.com",
        "port": 8003,
        "topic": "yl-home/${Home ID}/+/report"
    },
    "mqtt_monitor": {
        "url": "mqtt://monitor.industrialcamera.com",
        "port": 1883,
        "username": "",
        "password": "",
        "client_id": "monitor_client_id"
    },
    "receiver_type": "CHEKT",
    "chekt": {
        "api_token": "",
        "ip": "",
        "port": 30003
    },
    "sia": {
        "ip": "",
        "port": "",
        "account_id": "",
        "transmitter_id": "",
        "encryption_key": ""
    },
    "monitor": {"api_key": os.getenv("MONITOR_API_KEY", "")},
    "timezone": "UTC",
    "door_open_timeout": 30,
    "home_id": ""
}

def load_config():
    config_json = redis_client.get("config")
    if config_json:
        return json.loads(config_json)
    else:
        redis_client.set("config", json.dumps(DEFAULT_CONFIG))
        return DEFAULT_CONFIG

def save_config(data):
    redis_client.set("config", json.dumps(data))

def get_user_data(username):
    user_json = redis_client.get(f"user:{username}")
    return json.loads(user_json) if user_json else {}

def save_user_data(username, data):
    redis_client.set(f"user:{username}", json.dumps(data))