"""
Configuration management for the YoLink Dashboard RTSP Server.
Provides flexible configuration loading, validation, and update mechanisms.
"""

import os
import random
from dotenv import load_dotenv
import socket
import logging
import json
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path

# Configure basic logging until proper configuration is loaded
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)
load_dotenv()


def generate_random_mac() -> str:
    """Generate a random, valid MAC address in XX:XX:XX:XX:XX:XX format."""
    return ":".join("{:02X}".format(random.randint(0, 255)) for _ in range(6))


# Retrieve the MAC address from the environment; generate one if not provided.
MAC_ADDRESS = os.getenv("MAC_ADDRESS")
if not MAC_ADDRESS:
    MAC_ADDRESS = generate_random_mac()


class ConfigValidator:
    """
    Validates configuration settings and provides defaults.
    """

    @staticmethod
    def safe_int(value: Any, default: int, min_val: Optional[int] = None,
                 max_val: Optional[int] = None, name: Optional[str] = None) -> int:
        """
        Convert value to int safely with range validation.
        """
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

    @staticmethod
    def safe_bool(value: Any, default: bool = False, name: Optional[str] = None) -> bool:
        """
        Convert value to boolean safely.
        """
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            if value.lower() in ('true', 'yes', '1', 'y', 'on'):
                return True
            if value.lower() in ('false', 'no', '0', 'n', 'off'):
                return False

        if name:
            logger.warning(f"Invalid {name} boolean value: {value}, using default: {default}")
        return default

    @staticmethod
    def safe_enum(value: Any, allowed_values: List[Any], default: Any, name: Optional[str] = None) -> Any:
        """
        Validate value against an enumeration of allowed values.
        """
        if value in allowed_values:
            return value

        if name:
            logger.warning(f"Invalid {name} value: {value}, allowed values: {allowed_values}, using default: {default}")
        return default


class Configuration:
    """
    Configuration manager with thread-safe updates and validation.
    """

    def __init__(self, initial_config: Dict[str, Any] = None):
        """
        Initialize the configuration manager.
        """
        self._config = initial_config or {}
        self._lock = threading.RLock()
        self._validators = {}
        self._watchers = []

        # Register default validators
        self._register_default_validators()

    def _register_default_validators(self) -> None:
        """Register default validators for common configuration parameters."""
        # Network settings
        self.register_validator("rtsp_port",
            lambda v: ConfigValidator.safe_int(v, 554, 1, 65535, "RTSP_PORT"))
        self.register_validator("http_port",
            lambda v: ConfigValidator.safe_int(v, 80, 1, 65535, "HTTP_PORT"))
        self.register_validator("onvif_port",
            lambda v: ConfigValidator.safe_int(v, 8000, 1, 65535, "ONVIF_PORT"))
        self.register_validator("ws_port",
            lambda v: ConfigValidator.safe_int(v, 9999, 1, 65535, "WS_PORT"))

        # Video settings
        self.register_validator("width",
            lambda v: ConfigValidator.safe_int(v, 1920, 320, 3840, "WIDTH"))
        self.register_validator("height",
            lambda v: ConfigValidator.safe_int(v, 1080, 240, 2160, "HEIGHT"))
        self.register_validator("frame_rate",
            lambda v: ConfigValidator.safe_int(v, 6, 1, 30, "FRAME_RATE"))
        self.register_validator("bitrate",
            lambda v: ConfigValidator.safe_int(v, 500, 100, 20000, "BITRATE"))
        self.register_validator("quality",
            lambda v: ConfigValidator.safe_int(v, 5, 1, 10, "QUALITY"))
        self.register_validator("gop",
            lambda v: ConfigValidator.safe_int(v, 30, 1, 300, "GOP"))

        # Feature flag for ONVIF remains validated
        self.register_validator("enable_onvif",
            lambda v: ConfigValidator.safe_bool(v, True, "ENABLE_ONVIF"))

        # H.264 profile validation
        self.register_validator("h264_profile",
            lambda v: ConfigValidator.safe_enum(v, ["Baseline", "Main", "High"], "High", "H264_PROFILE"))

        # ONVIF auth method validation
        self.register_validator("onvif_auth_method",
            lambda v: ConfigValidator.safe_enum(v, ["basic", "ws-security", "both", "none"], "both", "ONVIF_AUTH_METHOD"))

    def register_validator(self, key: str, validator_func: callable) -> None:
        """
        Register a validation function for a configuration key.
        """
        with self._lock:
            self._validators[key] = validator_func

    def register_watcher(self, watcher_func: callable) -> None:
        """
        Register a function to be called when configuration changes.
        """
        with self._lock:
            self._watchers.append(watcher_func)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value with an optional default.
        """
        with self._lock:
            return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value with validation.
        """
        with self._lock:
            if key in self._validators:
                validated_value = self._validators[key](value)
                self._config[key] = validated_value
            else:
                self._config[key] = value

            config_copy = self._config.copy()

        for watcher in self._watchers:
            try:
                watcher(config_copy)
            except Exception as e:
                logger.error(f"Error in configuration watcher: {e}")

    def update(self, new_config: Dict[str, Any]) -> None:
        """
        Update multiple configuration values at once.
        """
        with self._lock:
            for key, value in new_config.items():
                if key in self._validators:
                    validated_value = self._validators[key](value)
                    self._config[key] = validated_value
                else:
                    self._config[key] = value

            config_copy = self._config.copy()

        for watcher in self._watchers:
            try:
                watcher(config_copy)
            except Exception as e:
                logger.error(f"Error in configuration watcher: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Get a copy of the entire configuration.
        """
        with self._lock:
            return self._config.copy()

    def load_from_file(self, file_path: str) -> bool:
        """
        Load configuration from a JSON file.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                logger.warning(f"Configuration file {file_path} does not exist")
                return False

            with open(file_path, 'r') as f:
                new_config = json.load(f)

            self.update(new_config)
            logger.info(f"Loaded configuration from {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load configuration from {file_path}: {e}")
            return False

    def save_to_file(self, file_path: str) -> bool:
        """
        Save current configuration to a JSON file.
        """
        try:
            with self._lock:
                config_copy = self._config.copy()

            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, 'w') as f:
                json.dump(config_copy, f, indent=2)

            logger.info(f"Saved configuration to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save configuration to {file_path}: {e}")
            return False


# Global configuration instance and lock
_config = None
_config_lock = threading.Lock()


def get_config() -> Dict[str, Any]:
    """
    Load application configuration from environment variables with sensible defaults.
    Uses a singleton pattern to avoid reloading multiple times.
    """
    global _config

    with _config_lock:
        if _config:
            return _config.to_dict()

        _config = Configuration()

        # Attempt to load configuration from a file if specified
        config_file = os.environ.get("CONFIG_FILE")
        if config_file:
            _config.load_from_file(config_file)

        # Detect server IP address
        try:
            server_ip = os.environ.get("SERVER_IP")
            if not server_ip:
                server_ip = socket.gethostbyname(socket.gethostname())
                logger.info(f"SERVER_IP not set, using detected IP: {server_ip}")
        except socket.gaierror:
            logger.warning("Could not determine hostname, using localhost as default")
            server_ip = "127.0.0.1"

        # Basic configuration from environment variables
        config = {
            # Dashboard configuration
            "dashboard_url": os.environ.get("DASHBOARD_URL", "http://websocket-proxy:3000"),

            # RTSP configuration
            "rtsp_port": os.environ.get("RTSP_PORT", 554),
            "stream_name": os.environ.get("STREAM_NAME", "yolink-dashboard"),

            # RTSP stream quality settings
            "bitrate": os.environ.get("BITRATE", 500),
            "quality": os.environ.get("QUALITY", 5),
            "gop": os.environ.get("GOP", 30),
            "h264_profile": os.environ.get("H264_PROFILE", "High"),

            # Rendering configuration
            "frame_rate": os.environ.get("FRAME_RATE", 6),
            "width": os.environ.get("WIDTH", 1920),
            "height": os.environ.get("HEIGHT", 1080),
            "cycle_interval": os.environ.get("CYCLE_INTERVAL", 10000),

            # HTTP API configuration
            "http_port": os.environ.get("RTSP_API_PORT", 3001),

            # WebSocket configuration
            "ws_port": os.environ.get("WS_PORT", 9999),

            # ONVIF configuration
            "enable_onvif": os.environ.get("ENABLE_ONVIF", "true"),
            "onvif_port": os.environ.get("ONVIF_PORT", 8000),
            "onvif_username": os.environ.get("ONVIF_USERNAME", "admin"),
            "onvif_password": os.environ.get("ONVIF_PASSWORD", "123456"),
            "onvif_auth_required": os.environ.get("ONVIF_AUTH_REQUIRED", "true"),
            "onvif_auth_method": os.environ.get("ONVIF_AUTH_METHOD", "both"),

            # Device information
            "manufacturer": os.environ.get("MANUFACTURER", "Industrial Camera Systems"),
            "model": os.environ.get("MODEL", "Dashboard-RTSP"),
            "firmware_version": os.environ.get("FIRMWARE_VERSION", "1.0.0"),
            "hardware_id": os.environ.get("HARDWARE_ID", "YOLINK-DASHBOARD-1"),

            # Server information
            "server_ip": server_ip,

            # Logging configuration
            "log_level": os.environ.get("LOG_LEVEL", "DEBUG"),

            # Resource monitoring
            "enable_resource_monitoring": os.environ.get("ENABLE_RESOURCE_MONITORING", "true"),

            # Profile name for the dashboard
            "profile_name": os.environ.get("PROFILE_NAME", "YoLink Dashboard"),

            # Store primary values for derived calculations
            "_primary_width": os.environ.get("WIDTH", 1920),
            "_primary_height": os.environ.get("HEIGHT", 1080),
            "_primary_bitrate": os.environ.get("BITRATE", 500),
            "_primary_fps": os.environ.get("FRAME_RATE", 6),
        }

        # Update configuration with values from environment
        _config.update(config)

        # Calculate dependent values for profiles
        primary_width = _config.get("width")
        primary_height = _config.get("height")
        primary_bitrate = _config.get("bitrate")
        primary_fps = _config.get("frame_rate")

        # Configure low-resolution and mobile profiles unconditionally
        profile_config = {
            # Low resolution profile settings
            "low_res_width": os.environ.get("LOW_RES_WIDTH", primary_width // 2),
            "low_res_height": os.environ.get("LOW_RES_HEIGHT", primary_height // 2),
            "low_res_fps": os.environ.get("LOW_RES_FPS", min(primary_fps, 4)),
            "low_res_bitrate": os.environ.get("LOW_RES_BITRATE", primary_bitrate // 4),
            "low_res_sensors_per_page": os.environ.get("LOW_RES_SENSORS_PER_PAGE", 6),

            # Mobile profile settings
            "mobile_width": os.environ.get("MOBILE_WIDTH", primary_width // 4),
            "mobile_height": os.environ.get("MOBILE_HEIGHT", primary_height // 4),
            "mobile_fps": os.environ.get("MOBILE_FPS", 6),
            "mobile_bitrate": os.environ.get("MOBILE_BITRATE", primary_bitrate // 10),
            "mobile_sensors_per_page": os.environ.get("MOBILE_SENSORS_PER_PAGE", 4),

            # Main profile dashboard layout
            "sensors_per_page": os.environ.get("SENSORS_PER_PAGE", 20),
        }

        # Update configuration with profile settings
        _config.update(profile_config)

        # Log configuration summary
        logger.info(
            f"Configuration loaded:"
            f"\n - Server: {_config.get('server_ip')}"
            f"\n - RTSP: Port={_config.get('rtsp_port')}, Stream={_config.get('stream_name')}"
            f"\n - RTSP Quality: Bitrate={_config.get('bitrate')}kbps, Quality={_config.get('quality')}, GOP={_config.get('gop')}"
            f"\n - Video: {_config.get('width')}x{_config.get('height')} @ {_config.get('frame_rate')}fps"
            f"\n - HTTP API: Port={_config.get('http_port')}"
            f"\n - ONVIF: Enabled={_config.get('enable_onvif')}, Port={_config.get('onvif_port')}"
        )

        # Log profile configurations (always enabled now)
        logger.info(
            f"Low-resolution profile: {_config.get('low_res_width')}x{_config.get('low_res_height')} @ {_config.get('low_res_fps')}fps"
        )
        logger.info(
            f"Mobile profile: {_config.get('mobile_width')}x{_config.get('mobile_height')} @ {_config.get('mobile_fps')}fps"
        )

        return _config.to_dict()


def reload_config() -> Dict[str, Any]:
    """
    Reload configuration from environment variables.
    Useful for runtime configuration updates.
    """
    global _config

    with _config_lock:
        _config = None
        return get_config()


def save_config(file_path: str) -> bool:
    """
    Save current configuration to a file.
    """
    global _config

    with _config_lock:
        if not _config:
            logger.error("Cannot save configuration: configuration not loaded")
            return False

        return _config.save_to_file(file_path)
