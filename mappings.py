import json
from typing import Dict, List, Optional
from db import redis_client
import logging
from utils import load_yaml, save_to_yaml

logger = logging.getLogger(__name__)

def initialize_mappings():
    """Initialize mappings in Redis if not present."""
    if redis_client.get("mappings") is None:
        redis_client.set("mappings", json.dumps({"mappings": []}))
        logger.info("Initialized empty mappings in Redis")

def get_mappings() -> Dict[str, List[Dict]]:
    """Retrieve all mappings from Redis."""
    mappings_json = redis_client.get("mappings")
    if mappings_json is None:
        return {"mappings": []}
    return json.loads(mappings_json)

def get_mapping(yolink_device_id: str) -> Optional[Dict]:
    """Retrieve a specific mapping by YoLink device ID."""
    mappings = get_mappings().get("mappings", [])
    return next((m for m in mappings if m["yolink_device_id"] == yolink_device_id), None)

def import_mappings_from_yaml(file_path: str):
    """Import mappings from a YAML file into Redis."""
    mappings_data = load_yaml(file_path)
    redis_client.set("mappings", json.dumps(mappings_data))
    logger.info(f"Imported mappings from {file_path} to Redis")

def export_mappings_to_yaml(file_path: str):
    """Export mappings from Redis to a YAML file."""
    mappings = get_mappings()
    save_to_yaml(file_path, mappings)
    logger.info(f"Exported mappings to {file_path}")

def load_mappings_to_redis(file_path='mappings.yaml'):
    """Load mappings into Redis from a YAML file, with fallback to empty mappings."""
    try:
        import_mappings_from_yaml(file_path)
    except Exception as e:
        logger.warning(f"No mappings.yaml found or error loading: {e}")
        initialize_mappings()  # Fallback to empty mappings

if __name__ == "__main__":
    initialize_mappings()