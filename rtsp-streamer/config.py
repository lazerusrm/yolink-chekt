"""
Configuration management for the YoLink Dashboard RTSP Server.
"""
import os
import socket
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


def get_config() -> Dict[str, Any]:
    """
    Load application configuration from environment variables with sensible defaults.

    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    try:
        server_ip = os.environ.get("SERVER_IP", socket.gethostbyname(socket.gethostname()))
    except socket.gaierror:
        logger.warning("Could not determine hostname, using localhost as default")
        server_ip = "127.0.0.1"

    config = {
        # Dashboard configuration
        "dashboard_url": os.environ.get("DASHBOARD_URL", "http://websocket-proxy:3000"),

        # RTSP configuration
        "rtsp_port": int(os.environ.get("RTSP_PORT", 8554)),
        "stream_name": os.environ.get("STREAM_NAME", "yolink-dashboard"),

        # Rendering configuration
        "frame_rate": int(os.environ.get("FRAME_RATE", 6)),
        "width": int(os.environ.get("WIDTH", 1920)),
        "height": int(os.environ.get("HEIGHT", 1080)),
        "cycle_interval": int(os.environ.get("CYCLE_INTERVAL", 10000)),

        # HTTP API configuration
        "http_port": int(os.environ.get("RTSP_API_PORT", 3001)),

        # WebSocket configuration
        "ws_port": int(os.environ.get("WS_PORT", 9999)),

        # ONVIF configuration
        "enable_onvif": os.environ.get("ENABLE_ONVIF", "true").lower() != "false",
        "onvif_port": int(os.environ.get("ONVIF_PORT", 8555)),

        # Server information
        "server_ip": server_ip,
    }

    logger.info(f"Loaded configuration: RTSP Port={config['rtsp_port']}, "
                f"HTTP Port={config['http_port']}, "
                f"ONVIF Enabled={config['enable_onvif']}")

    return config