import logging
import time
import threading
import requests
from config import load_config
import traceback

# Import for PyModbus 3.x
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException, ConnectionException

logger = logging.getLogger(__name__)

# Global client to reuse connection
client = None
connected = False
last_connection_attempt = 0
connection_retry_interval = 10  # seconds
unit_id = 1  # Default unit ID, will be updated from config


def configure_proxy(target_ip, target_port):
    """
    Configure the Modbus proxy to connect to the specified target

    Args:
        target_ip (str): The IP address of the target Modbus device
        target_port (int): The port number of the target Modbus device

    Returns:
        bool: True if configuration was successful, False otherwise
    """
    # Configuration data
    data = {
        "target_ip": target_ip,
        "target_port": target_port
    }

    # Different URLs to try
    urls_to_try = [
        "http://modbus-proxy:5000/api/modbus-proxy/configure",
        "http://modbus-proxy:5000/configure",
        "http://modbus-proxy:1502/api/modbus-proxy/configure",
        "http://modbus-proxy:1502/configure"
    ]

    for url in urls_to_try:
        try:
            logger.debug(f"Attempting to configure modbus proxy at {url}")
            response = requests.post(
                url,
                json=data,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                logger.info(f"Successfully configured modbus proxy at {url}")
                return True
            else:
                logger.warning(f"Failed to configure modbus proxy at {url}: {response.status_code} - {response.text}")
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error to {url}: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error to {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error configuring modbus proxy at {url}: {e}")

    # All attempts failed
    logger.error(f"All attempts to configure modbus proxy failed")
    return False


def check_proxy_health():
    """
    Check if the Modbus proxy is healthy

    Returns:
        bool: True if proxy is healthy, False otherwise
    """
    # Try both ports
    urls_to_try = [
        "http://modbus-proxy:5000/healthcheck",
        "http://modbus-proxy:1502/healthcheck"
    ]

    for url in urls_to_try:
        try:
            logger.debug(f"Checking modbus proxy health at {url}")
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy" and data.get("proxy_running", False):
                    logger.debug("Modbus proxy is healthy")
                    return True
            logger.warning(f"Modbus proxy health check failed at {url}: {response.status_code}")
        except Exception as e:
            logger.warning(f"Modbus proxy health check error at {url}: {e}")

    return False


def ensure_connection():
    """
    Ensures that we have a valid connection to the Modbus relay.

    Returns:
        bool: True if connection is valid, False otherwise
    """
    global client, connected, last_connection_attempt, unit_id

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

    # Update the global unit_id
    try:
        unit_id = int(modbus_config.get('unit_id', 1))
    except (ValueError, TypeError):
        unit_id = 1
        logger.warning(f"Invalid unit_id in config, using default: 1")

    # First check if proxy is healthy
    if not check_proxy_health():
        logger.warning("Modbus proxy is not available or running")
        # Let's try again with configuration anyway

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

        # Create client - no slave parameter for this version of PyModbus
        client = ModbusTcpClient(
            host="modbus-proxy",  # Connect to the proxy service in the Docker network
            port=1502,  # Proxy listen port
            timeout=10
        )

        # Attempt connection
        connected = client.connect()
        if connected:
            # Validate connection with a test read
            try:
                # For PyModbus 3.x we need to use a transaction or set a default slave
                from pymodbus.payload import BinaryPayloadBuilder
                from pymodbus.constants import Endian
                from pymodbus.transaction import ModbusRtuFramer

                # Try unit parameter in the actual read call
                try:
                    result = client.read_coils(0, 1, unit=unit_id)
                    if hasattr(result, 'bits'):
                        logger.info(f"Successfully connected to Modbus device via proxy using unit parameter")
                        return True
                except TypeError:
                    # If unit parameter doesn't work, try different methods
                    logger.warning("unit parameter not supported in read_coils, trying alternatives")

                # Try using client properties if available
                if hasattr(client, 'unit_id'):
                    client.unit_id = unit_id
                elif hasattr(client, 'slave'):
                    client.slave = unit_id

                # Try reading without unit parameter after setting properties
                result = client.read_coils(0, 1)

                if hasattr(result, 'bits'):
                    logger.info(f"Successfully connected to Modbus device via proxy")
                    return True
                else:
                    logger.warning(f"Modbus read test failed: {result}")
                    connected = False
                    return False
            except Exception as e:
                logger.error(f"Error validating Modbus connection: {e}")
                traceback.print_exc()
                connected = False
                return False
        else:
            logger.error(f"Failed to connect to Modbus proxy")
            return False
    except Exception as e:
        logger.error(f"Error connecting to Modbus proxy: {e}")
        traceback.print_exc()
        connected = False
        return False


def trigger_relay(channel, state=True, pulse_seconds=None, follower_mode=None):
    """
    Trigger a relay channel with improved reliability.

    Args:
        channel (int): The relay channel number (1-16)
        state (bool): True to turn relay on, False to turn it off
        pulse_seconds (float, optional): If provided, relay will turn on for this time then turn off
        follower_mode (bool, optional): Override global follower_mode setting

    Returns:
        bool: True if successful, False otherwise
    """
    global unit_id

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

        # Write to coil with retry logic
        write_attempts = 3
        for attempt in range(write_attempts):
            try:
                logger.info(f"Setting relay channel {channel} to {'ON' if state else 'OFF'} (attempt {attempt + 1})")

                # Try with unit parameter first
                try:
                    result = client.write_coil(coil_address, state, unit=unit_id)
                except TypeError:
                    # If unit parameter doesn't work
                    result = client.write_coil(coil_address, state)

                if not result or hasattr(result, 'isError') and result.isError():
                    logger.error(f"Failed to set relay (attempt {attempt + 1}): {result}")
                    if attempt < write_attempts - 1:
                        # Try reconnecting before the next attempt
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
                            # Use a new connection instance for the delayed operation
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
                    redis_client.set(f"relay_state_timestamp:{channel}", str(time.time()))
                except Exception as e:
                    logger.error(f"Failed to store relay state in Redis: {e}")

                return True

            except ConnectionException as e:
                logger.error(f"Connection lost during relay operation (attempt {attempt + 1}): {e}")
                connected = False
                if attempt < write_attempts - 1:
                    ensure_connection()
                    time.sleep(1)
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
    """
    Read the current state of a relay channel.

    Args:
        channel (int): The relay channel number (1-16)

    Returns:
        bool or None: True if relay is on, False if off, None if error
    """
    global unit_id

    if not ensure_connection():
        logger.error("Cannot read relay state: No connection to Modbus relay")
        return None

    config = load_config()
    modbus_config = config.get('modbus', {})

    # Validate channel number
    max_channels = modbus_config.get('max_channels', 16)
    if not 1 <= channel <= max_channels:
        logger.error(f"Invalid relay channel: {channel}. Must be between 1 and {max_channels}")
        return None

    # Adjust channel number for zero-based addressing in Modbus
    coil_address = channel - 1

    try:
        # Try with unit parameter first
        try:
            result = client.read_coils(coil_address, 1, unit=unit_id)
        except TypeError:
            # If unit parameter doesn't work
            result = client.read_coils(coil_address, 1)

        if hasattr(result, 'bits'):
            state = result.bits[0]
            logger.debug(f"Relay channel {channel} is {'ON' if state else 'OFF'}")
            return state
        else:
            logger.error(f"Failed to read relay channel {channel}: {result}")
            return None
    except ConnectionException as e:
        logger.error(f"Connection to Modbus relay lost: {e}")
        connected = False
        return None
    except ModbusException as e:
        logger.error(f"Modbus error when reading relay channel {channel}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when reading relay channel {channel}: {e}")
        traceback.print_exc()
        return None


def read_all_relay_states():
    """
    Read the state of all relay channels.

    Returns:
        list or None: List of booleans representing relay states, None if error
    """
    global unit_id

    if not ensure_connection():
        logger.error("Cannot read relay states: No connection to Modbus relay")
        return None

    config = load_config()
    modbus_config = config.get('modbus', {})
    max_channels = modbus_config.get('max_channels', 16)

    try:
        # Try with unit parameter first
        try:
            result = client.read_coils(0, max_channels, unit=unit_id)
        except TypeError:
            # If unit parameter doesn't work
            result = client.read_coils(0, max_channels)

        if hasattr(result, 'bits'):
            states = list(result.bits)[:max_channels]  # Limit to actual number of channels
            logger.debug(f"All relay states: {states}")
            return states
        else:
            logger.error(f"Failed to read all relay states: {result}")
            return None
    except ConnectionException as e:
        logger.error(f"Connection to Modbus relay lost: {e}")
        connected = False
        return None
    except ModbusException as e:
        logger.error(f"Modbus error when reading all relay states: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when reading all relay states: {e}")
        traceback.print_exc()
        return None


def initialize():
    """Initialize the Modbus relay connection with health monitoring."""
    global connection_retry_interval

    logger.info("Initializing Modbus relay with PyModbus 3.x API (alternative method)")

    # Start a background thread to periodically check connection health
    def health_monitor():
        while True:
            try:
                if not connected and ensure_connection():
                    logger.info("Modbus connection restored by health monitor")
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in Modbus health monitor: {e}")
                time.sleep(60)  # Longer delay after error

    # Start the health monitor thread
    monitor_thread = threading.Thread(target=health_monitor, daemon=True)
    monitor_thread.start()

    # Attempt initial connection
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