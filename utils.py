import yaml
import os

def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}

def save_to_yaml(file_path, data):
    with open(file_path, 'w') as file:
        yaml.dump(data, file)