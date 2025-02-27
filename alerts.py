import logging
from mappings import get_mapping

logger = logging.getLogger()

def trigger_alert(device_id, state, device_type):
    mapping = get_mapping(device_id)
    if not mapping:
        logger.warning(f"No mapping for device {device_id}")
        return
    # Simplified logic for brevity
    logger.info(f"Alert triggered for {device_id}: {state}")

def trigger_chekt_event(device_id, event_description, chekt_zone):
    logger.info(f"CHEKT event: {event_description} on zone {chekt_zone}")

def send_sia_message(device_id, event_description, zone, sia_config):
    logger.info(f"SIA message: {event_description} on zone {zone}")