import logging
import time
import threading
import requests
from config import load_config
import traceback

logger = logging.getLogger(__name__)

# Global client to reuse connection
client = None
connected = False
last_connection_attempt = 0
connection_retry_interval = 10  # seconds


def configure_proxy(target_ip, target_port):
    """Configure the Modbus proxy to connect to the specified target"""
    data = {
        "target_ip": target_ip,
        "target_port": target_port
    }

    url = "http://modbus-proxy:5000/api/modbus-proxy/configure"

    try:
        logger.debug(f"Configuring modbus proxy at {url} for target {target_ip}:{target_port}")
        response = requests.post(url, json=data, timeout=5)

        if response.status_code == 200:
            logger.info(f"Successfully configured modbus proxy")
            return True
        else:
            logger.warning(f"Failed to configure modbus proxy: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error configuring modbus proxy: {e}")
        return False


def check_proxy_health():
    """Check if the Modbus proxy is healthy"""
    url = "http://modbus-proxy:5000/healthcheck"

    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return True
        return False
    except Exception as e:
        logger.warning(f"Modbus proxy health check error: {e}")
        return False


def ensure_connection():
    """Ensures that we have a valid connection to the Modbus relay."""
    global client, connected, last_connection_attempt

    # Rate limit connection attempts
    current_time = time.time()
    if current_time - last_connection_attempt < connection_retry_interval and not connected:
        logger.debug("Connection attempt too soon after previous failure, skipping")
        return False

    last_connection_attempt = current_time

    # Get configuration
    config = load_config()
    modbus_config = config.get('modbus', {})

    # Early check if Modbus is enabled
    if not modbus_config.get('enabled', False):
        logger.info("Modbus relay is not enabled in configuration")
        connected = False
        return False

    # Get connection details
    modbus_ip = modbus_config.get('ip')
    if not modbus_ip or modbus_ip.strip() == "":
        logger.warning("Modbus relay IP not configured")
        connected = False
        return False

    modbus_port = modbus_config.get('port', 502)

    # Configure the proxy with the target device information
    if not configure_proxy(modbus_ip, modbus_port):
        logger.error("Failed to configure modbus proxy")
        connected = False
        return False

    # Connect to the proxy service
    try:
        # Close any existing client
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing existing Modbus connection: {e}")

        logger.info(f"Connecting to Modbus relay via proxy for device at {modbus_ip}:{modbus_port}")

        # Create ModbusTcpClient - don't try to set slave/unit here
        # Import client every time to make sure we're using the right one
        from pymodbus.client import ModbusTcpClient

        client = ModbusTcpClient(
            host="modbus-proxy",  # Connect to the proxy service in the Docker network
            port=1502,  # Proxy listen port
            timeout=10
        )

        # Attempt connection
        connected = client.connect()
        if connected:
            logger.info(f"Successfully connected to Modbus proxy")
            return True
        else:
            logger.error(f"Failed to connect to Modbus proxy")
            return False
    except Exception as e:
        logger.error(f"Error connecting to Modbus proxy: {e}")
        traceback.print_exc()
        connected = False
        return False


def trigger_relay(channel, state=True, pulse_seconds=None, follower_mode=None):
    """Trigger a relay channel."""
    try:
        # Ensure connection with retries
        connection_attempts = 3
        for attempt in range(connection_attempts):
            if ensure_connection():
                break
            elif attempt < connection_attempts - 1:
                logger.info(f"Retrying connection for relay trigger (attempt {attempt + 1})")
                time.sleep(1)
            else:
                logger.error("Could not establish Modbus connection for trigger operation")
                return False

        # Get configuration
        config = load_config()
        modbus_config = config.get('modbus', {})

        # Check follower mode
        if follower_mode is None:
            follower_mode = modbus_config.get('follower_mode', False)

        # Validate channel
        try:
            max_channels = int(modbus_config.get('max_channels', 16))
        except (ValueError, TypeError):
            max_channels = 16

        if not isinstance(channel, int):
            try:
                channel = int(channel)
            except (ValueError, TypeError):
                logger.error(f"Invalid relay channel: {channel}. Must be a number.")
                return False

        if not 1 <= channel <= max_channels:
            logger.error(f"Invalid relay channel: {channel}. Must be between 1 and {max_channels}")
            return False

        # Adjust channel number for zero-based addressing in Modbus
        coil_address = channel - 1

        # Get unit ID
        unit_id = 1
        try:
            unit_id = int(modbus_config.get('unit_id', 1))
        except (ValueError, TypeError):
            unit_id = 1
            logger.warning(f"Invalid unit_id in config, using default: 1")

        # Write to coil with retry logic
        write_attempts = 3
        for attempt in range(write_attempts):
            try:
                logger.info(f"Setting relay channel {channel} to {'ON' if state else 'OFF'} (attempt {attempt + 1})")

                # Write directly to the specified address
                result = client.write_coil(coil_address, state)

                if hasattr(result, 'isError') and result.isError():
                    logger.error(f"Failed to set relay (attempt {attempt + 1}): {result}")
                    if attempt < write_attempts - 1:
                        ensure_connection()
                        time.sleep(1)
                    continue

                # Success!
                logger.info(f"Successfully set relay channel {channel} to {'ON' if state else 'OFF'}")

                # Handle pulse mode
                if not follower_mode and pulse_seconds and state:
                    def turn_off_later():
                        try:
                            logger.info(f"Waiting {pulse_seconds} seconds before turning off relay {channel}")
                            time.sleep(pulse_seconds)
                            logger.info(f"Turning off relay channel {channel} after pulse")
                            trigger_relay(channel, False)
                        except Exception as e:
                            logger.error(f"Error in pulse timer for channel {channel}: {e}")

                    # Start a thread to turn off the relay after the specified time
                    turn_off_thread = threading.Thread(target=turn_off_later, daemon=True)
                    turn_off_thread.start()

                # Store the current relay state in Redis
                try:
                    from db import redis_client
                    redis_client.set(f"relay_state:{channel}", "1" if state else "0")
                except Exception as e:
                    logger.error(f"Failed to store relay state in Redis: {e}")

                return True

            except Exception as e:
                logger.error(f"Unexpected error setting relay (attempt {attempt + 1}): {e}")
                traceback.print_exc()
                if attempt < write_attempts - 1:
                    time.sleep(1)

        # All attempts failed
        logger.error(f"Failed to set relay channel {channel} after {write_attempts} attempts")
        return False

    except Exception as e:
        logger.error(f"Critical error in trigger_relay: {e}")
        traceback.print_exc()
        return False


def read_relay_state(channel):
    """Read the current state of a relay channel."""
    if not ensure_connection():
        logger.error("Cannot read relay state: No connection to Modbus relay")
        return None

    # Validate channel number
    config = load_config()
    modbus_config = config.get('modbus', {})
    max_channels = modbus_config.get('max_channels', 16)

    if not 1 <= channel <= max_channels:
        logger.error(f"Invalid relay channel: {channel}. Must be between 1 and {max_channels}")
        return None

    # Adjust channel number for zero-based addressing in Modbus
    coil_address = channel - 1

    try:
        # Read the coil state
        result = client.read_coils(coil_address, 1)

        if hasattr(result, 'bits'):
            state = result.bits[0]
            logger.debug(f"Relay channel {channel} is {'ON' if state else 'OFF'}")
            return state
        else:
            logger.error(f"Failed to read relay channel {channel}")
            return None
    except Exception as e:
        logger.error(f"Error reading relay channel {channel}: {e}")
        traceback.print_exc()
        return None


def read_all_relay_states():
    """Read the state of all relay channels."""
    if not ensure_connection():
        logger.error("Cannot read relay states: No connection to Modbus relay")
        return None

    config = load_config()
    modbus_config = config.get('modbus', {})
    max_channels = modbus_config.get('max_channels', 16)

    try:
        # Read all coil states
        result = client.read_coils(0, max_channels)

        if hasattr(result, 'bits'):
            states = list(result.bits)[:max_channels]
            logger.debug(f"All relay states: {states}")
            return states
        else:
            logger.error(f"Failed to read all relay states")
            return None
    except Exception as e:
        logger.error(f"Error reading all relay states: {e}")
        traceback.print_exc()
        return None


def initialize():
    """Initialize the Modbus relay connection."""
    # Import PyModbus to check version
    try:
        import pymodbus
        if hasattr(pymodbus, '__version__'):
            logger.info(f"PyModbus version: {pymodbus.__version__}")
    except ImportError:
        logger.error("PyModbus library not installed")
        return False

    logger.info("Initializing Modbus relay connection")

    # Simple initialization - just try to connect
    return ensure_connection()


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Test connection
    initialize()

    # Test triggering relays
    for i in range(1, 9):
        trigger_relay(i, True)
        time.sleep(0.5)
        trigger_relay(i, False)
        time.sleep(0.5)