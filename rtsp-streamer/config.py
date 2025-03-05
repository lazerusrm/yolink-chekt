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
        server_ip = os.environ.get("SERVER_IP")
        if not server_ip:
            server_ip = socket.gethostbyname(socket.gethostname())
            logger.info(f"SERVER_IP not set, using detected IP: {server_ip}")
    except socket.gaierror:
        logger.warning("Could not determine hostname, using localhost as default")
        server_ip = "127.0.0.1"

    # Helper function for safe int conversion
    def safe_int(value, default, min_val=None, max_val=None, name=None):
        try:
            result = int(value)
            if min_val is not None and result < min_val:
                logger.warning(f"{name} value {result} below minimum {min_val}, using minimum value")
                return min_val
            if max_val is not None and result > max_val:
                logger.warning(f"{name} value {result} above maximum {max_val}, using maximum value")
                return max_val
            return result
        except (ValueError, TypeError):
            if name:
                logger.warning(f"Invalid {name} value: {value}, using default: {default}")
            return default

    # Basic configuration
    config = {
        # Dashboard configuration
        "dashboard_url": os.environ.get("DASHBOARD_URL", "http://websocket-proxy:3000"),

        # RTSP configuration
        "rtsp_port": safe_int(os.environ.get("RTSP_PORT"), 8554, 1, 65535, "RTSP_PORT"),
        "stream_name": os.environ.get("STREAM_NAME", "yolink-dashboard"),

        # RTSP stream quality settings
        "bitrate": safe_int(os.environ.get("BITRATE"), 500, 100, 1000, "BITRATE"),  # RTSP bitrate in kbps (100-20000)
        "quality": safe_int(os.environ.get("QUALITY"), 5, 1, 10, "QUALITY"),  # RTSP quality (1-10)
        "gop": safe_int(os.environ.get("GOP"), 30, 1, 300, "GOP"),  # Group of Pictures length (1-300)
        "h264_profile": os.environ.get("H264_PROFILE", "High"),  # H.264 profile (Baseline, Main, High)

        # Rendering configuration
        "frame_rate": safe_int(os.environ.get("FRAME_RATE"), 6, 1, 10, "FRAME_RATE"),
        "width": safe_int(os.environ.get("WIDTH"), 1920, 320, 3840, "WIDTH"),
        "height": safe_int(os.environ.get("HEIGHT"), 1080, 240, 2160, "HEIGHT"),
        "cycle_interval": safe_int(os.environ.get("CYCLE_INTERVAL"), 10000, 1000, 3600000, "CYCLE_INTERVAL"),

        # HTTP API configuration
        "http_port": safe_int(os.environ.get("RTSP_API_PORT"), 3001, 1, 65535, "RTSP_API_PORT"),

        # WebSocket configuration
        "ws_port": safe_int(os.environ.get("WS_PORT"), 9999, 1, 65535, "WS_PORT"),

        # ONVIF configuration
        "enable_onvif": os.environ.get("ENABLE_ONVIF", "true").lower() != "false",
        "onvif_port": safe_int(os.environ.get("ONVIF_PORT"), 8555, 1, 65535, "ONVIF_PORT"),
        "onvif_username": os.environ.get("ONVIF_USERNAME", "admin"),
        "onvif_password": os.environ.get("ONVIF_PASSWORD", "123456"),
        "onvif_auth_required": os.environ.get("ONVIF_AUTH_REQUIRED", "true").lower() != "false",
        "onvif_auth_method": os.environ.get("ONVIF_AUTH_METHOD", "both"),  # "basic", "ws-security", "both", or "none"

        # Device information
        "manufacturer": os.environ.get("MANUFACTURER", "YoLink"),
        "model": os.environ.get("MODEL", "Dashboard-RTSP"),
        "firmware_version": os.environ.get("FIRMWARE_VERSION", "1.0.0"),
        "hardware_id": os.environ.get("HARDWARE_ID", "YOLINK-DASHBOARD-1"),

        # Server information
        "server_ip": server_ip,
    }

    # Validate authentication method
    if config["onvif_auth_method"] not in ["basic", "ws-security", "both", "none"]:
        logger.warning(f"Invalid ONVIF_AUTH_METHOD: {config['onvif_auth_method']}, using 'both'")
        config["onvif_auth_method"] = "both"

    # Validate H.264 profile
    if config["h264_profile"] not in ["Baseline", "Main", "High"]:
        logger.warning(f"Invalid H264_PROFILE: {config['h264_profile']}, using 'High'")
        config["h264_profile"] = "High"

    # Store base values for relative calculations
    primary_width = config["width"]
    primary_height = config["height"]
    primary_bitrate = config["bitrate"]
    primary_fps = config["frame_rate"]

    # Add multi-profile configuration
    config.update({
        # Additional ONVIF profile options
        "enable_low_res_profile": os.environ.get("ENABLE_LOW_RES_PROFILE", "false").lower() == "true",
        "profile_name": os.environ.get("PROFILE_NAME", "YoLink Dashboard"),

        # Low resolution profile settings
        "low_res_width": safe_int(os.environ.get("LOW_RES_WIDTH"), primary_width // 2, 320, None, "LOW_RES_WIDTH"),
        "low_res_height": safe_int(os.environ.get("LOW_RES_HEIGHT"), primary_height // 2, 240, None, "LOW_RES_HEIGHT"),
        "low_res_fps": safe_int(os.environ.get("LOW_RES_FPS"), min(primary_fps, 4), 1, 30, "LOW_RES_FPS"),
        "low_res_bitrate": safe_int(os.environ.get("LOW_RES_BITRATE"), primary_bitrate // 4, 100, None, "LOW_RES_BITRATE"),
        "low_res_sensors_per_page": safe_int(os.environ.get("LOW_RES_SENSORS_PER_PAGE"), 6, 1, 20, "LOW_RES_SENSORS_PER_PAGE"),

        # Mobile profile settings
        "enable_mobile_profile": os.environ.get("ENABLE_MOBILE_PROFILE", "false").lower() == "true",
        "mobile_width": safe_int(os.environ.get("MOBILE_WIDTH"), primary_width // 4, 160, None, "MOBILE_WIDTH"),
        "mobile_height": safe_int(os.environ.get("MOBILE_HEIGHT"), primary_height // 4, 120, None, "MOBILE_HEIGHT"),
        "mobile_fps": safe_int(os.environ.get("MOBILE_FPS"), 6, 1, 15, "MOBILE_FPS"),
        "mobile_bitrate": safe_int(os.environ.get("MOBILE_BITRATE"), primary_bitrate // 10, 50, None, "MOBILE_BITRATE"),
        "mobile_sensors_per_page": safe_int(os.environ.get("MOBILE_SENSORS_PER_PAGE"), 4, 1, 10, "MOBILE_SENSORS_PER_PAGE"),

        # Main profile dashboard layout
        "sensors_per_page": safe_int(os.environ.get("SENSORS_PER_PAGE"), 20, 1, 50, "SENSORS_PER_PAGE"),
    })

    # Log configuration summary
    logger.info(f"Configuration loaded:"
                f"\n - Server: {config['server_ip']}"
                f"\n - RTSP: Port={config['rtsp_port']}, Stream={config['stream_name']}"
                f"\n - RTSP Quality: Bitrate={config['bitrate']}kbps, Quality={config['quality']}, GOP={config['gop']}"
                f"\n - Video: {config['width']}x{config['height']} @ {config['frame_rate']}fps"
                f"\n - HTTP API: Port={config['http_port']}"
                f"\n - ONVIF: Enabled={config['enable_onvif']}, Port={config['onvif_port']}"
                f"\n - ONVIF Auth: Required={config['onvif_auth_required']}, Method={config['onvif_auth_method']}")

    # Log multi-profile configuration if enabled
    if config["enable_low_res_profile"]:
        logger.info(f"Low-resolution profile enabled: {config['low_res_width']}x{config['low_res_height']} @ {config['low_res_fps']}fps")

    if config["enable_mobile_profile"]:
        logger.info(f"Mobile profile enabled: {config['mobile_width']}x{config['mobile_height']} @ {config['mobile_fps']}fps")

    return config