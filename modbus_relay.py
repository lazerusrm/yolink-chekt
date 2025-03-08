import logging
import time
import threading
import requests
from config import load_config
import traceback
import json
from datetime import datetime

logger = logging.getLogger(__name__)

# Global client to reuse connection
client = None
connected = False
last_connection_attempt = 0
connection_retry_interval = 10  # seconds
health_check_interval = 30  # seconds
connection_monitor_running = False
connection_monitor_thread = None
proxy_endpoints = [
    "http://modbus-proxy:5000/api/modbus-proxy/configure",
    "http://modbus-proxy:5000/configure",
    "http://localhost:5000/api/modbus-proxy/configure"
]
health_check_endpoints = [
    "http://modbus-proxy:5000/healthcheck",
    "http://modbus-proxy:5000/api/modbus-proxy/status",
    "http://localhost:5000/healthcheck"
]


def configure_proxy(target_ip, target_port):
    """Configure the Modbus proxy to connect to the specified target with fallback options"""
    data = {
        "target_ip": target_ip,
        "target_port": target_port,
        "enabled": True
    }

    # Try all endpoints in sequence until one works
    for endpoint in proxy_endpoints:
        try:
            logger.debug(f"Configuring modbus proxy at {endpoint} for target {target_ip}:{target_port}")
            response = requests.post(endpoint, json=data, timeout=5)

            if response.status_code == 200:
                logger.info(f"Successfully configured modbus proxy via {endpoint}")
                return True
            else:
                logger.warning(
                    f"Failed to configure modbus proxy via {endpoint}: {response.status_code} - {response.text}")
        except Exception as e:
            logger.warning(f"Error configuring modbus proxy via {endpoint}: {e}")

    # If we got here, all attempts failed
    logger.error(f"All attempts to configure modbus proxy failed")
    return False


def check_proxy_health():
    """Check if the Modbus proxy is healthy with fallback options"""
    for endpoint in health_check_endpoints:
        try:
            response = requests.get(endpoint, timeout=2)
            if response.status_code == 200:
                logger.debug(f"Modbus proxy health check via {endpoint} successful")
                return True
            logger.warning(f"Modbus proxy health check via {endpoint} failed with status code {response.status_code}")
        except Exception as e:
            logger.warning(f"Modbus proxy health check via {endpoint} error: {e}")

    # If we got here, all health checks failed
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
    start_time = time.time()
    try:
        # Ensure connection with retries
        connection_attempts = 3
        for attempt in range(connection_attempts):
            if ensure_connection():
                break
            elif attempt < connection_attempts - 1:
                logger.info(f"Retrying connection for relay trigger (attempt {attempt + 1})")
                time.sleep(0.5)  # Reduced wait time for better responsiveness
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
                result = client.write_coil(coil_address, state, unit=unit_id)

                if hasattr(result, 'isError') and result.isError():
                    logger.error(f"Failed to set relay (attempt {attempt + 1}): {result}")
                    if attempt < write_attempts - 1:
                        ensure_connection()
                        time.sleep(0.5)  # Reduced wait time
                    continue

                # Success!
                logger.info(f"Successfully set relay channel {channel} to {'ON' if state else 'OFF'}")
                end_time = time.time()
                logger.debug(f"Relay operation completed in {end_time - start_time:.3f} seconds")

                # Store the current relay state with timestamp in Redis
                try:
                    from db import redis_client
                    timestamp = datetime.now().isoformat()
                    relay_state_data = {
                        "state": 1 if state else 0,
                        "timestamp": timestamp,
                        "channel": channel
                    }
                    redis_client.set(f"relay_state:{channel}", json.dumps(relay_state_data))
                    logger.debug(f"Stored relay state in Redis with timestamp: {timestamp}")
                except Exception as e:
                    logger.error(f"Failed to store relay state in Redis: {e}")

                # Special handling for testing in follower mode
                # For testing, we'll force a pulse behavior even in follower mode
                is_test_operation = pulse_seconds is not None and pulse_seconds < 10  # Assume it's a test if pulse is short

                # Handle pulse mode or test mode
                if (not follower_mode and pulse_seconds and state) or (follower_mode and is_test_operation and state):
                    def turn_off_later():
                        try:
                            actual_pulse = min(pulse_seconds,
                                               1.0) if follower_mode and is_test_operation else pulse_seconds
                            logger.info(f"Waiting {actual_pulse} seconds before turning off relay {channel}")
                            time.sleep(actual_pulse)
                            logger.info(f"Turning off relay channel {channel} after pulse")
                            # Call trigger_relay with follower_mode=False to ensure it turns off
                            trigger_relay(channel, False, follower_mode=False)
                        except Exception as e:
                            logger.error(f"Error in pulse timer for channel {channel}: {e}")

                    # Start a thread to turn off the relay after the specified time
                    turn_off_thread = threading.Thread(target=turn_off_later, daemon=True)
                    turn_off_thread.start()

                return True

            except Exception as e:
                logger.error(f"Unexpected error setting relay (attempt {attempt + 1}): {e}")
                traceback.print_exc()
                if attempt < write_attempts - 1:
                    time.sleep(0.5)  # Reduced wait time

        # All attempts failed
        logger.error(f"Failed to set relay channel {channel} after {write_attempts} attempts")
        return False

    except Exception as e:
        end_time = time.time()
        logger.error(f"Critical error in trigger_relay after {end_time - start_time:.3f} seconds: {e}")
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

    # Get unit ID
    unit_id = 1
    try:
        unit_id = int(modbus_config.get('unit_id', 1))
    except (ValueError, TypeError):
        unit_id = 1

    try:
        # Read the coil state
        result = client.read_coils(coil_address, 1, unit=unit_id)

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

    # Get unit ID
    unit_id = 1
    try:
        unit_id = int(modbus_config.get('unit_id', 1))
    except (ValueError, TypeError):
        unit_id = 1

    try:
        # Read all coil states
        result = client.read_coils(0, max_channels, unit=unit_id)

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


def connection_monitor():
    """
    Background thread function that continuously monitors the Modbus connection
    and tries to reconnect if the connection is lost.
    """
    global connection_monitor_running, connected
    connection_monitor_running = True
    logger.info("Modbus connection monitor started")

    while connection_monitor_running:
        try:
            # Only check and attempt reconnection if we're not currently connected
            if not connected:
                logger.info("Connection monitor detected disconnected state, attempting to reconnect")
                ensure_connection()
            else:
                # Periodically validate the connection by reading relay states
                try:
                    if client and client.is_socket_open():
                        # Do a simple read operation to verify connection is healthy
                        config = load_config()
                        modbus_config = config.get('modbus', {})

                        if modbus_config.get('enabled', False):
                            logger.debug("Connection monitor performing health check")
                            # Read the first coil as a test
                            unit_id = int(modbus_config.get('unit_id', 1))
                            result = client.read_coils(0, 1, unit=unit_id)

                            if not hasattr(result, 'bits'):
                                logger.warning("Connection monitor: connection test failed, reconnecting")
                                connected = False
                                ensure_connection()
                        else:
                            # If Modbus is disabled in config, stop the monitor
                            logger.info("Modbus disabled in config, stopping connection monitor")
                            connection_monitor_running = False
                            break
                    else:
                        logger.warning("Connection monitor: socket not open, reconnecting")
                        connected = False
                        ensure_connection()
                except Exception as e:
                    logger.warning(f"Connection monitor: health check failed: {e}")
                    connected = False
                    ensure_connection()

        except Exception as e:
            logger.error(f"Error in connection monitor: {e}")

        # Sleep before next check
        time.sleep(health_check_interval)

    logger.info("Modbus connection monitor stopped")


def start_connection_monitor():
    """Start the connection monitoring thread if it's not already running"""
    global connection_monitor_thread, connection_monitor_running

    if connection_monitor_thread is None or not connection_monitor_thread.is_alive():
        connection_monitor_running = True
        connection_monitor_thread = threading.Thread(target=connection_monitor, daemon=True)
        connection_monitor_thread.start()
        logger.info("Started Modbus connection monitor thread")
        return True
    else:
        logger.debug("Connection monitor already running")
        return False


def stop_connection_monitor():
    """Stop the connection monitoring thread"""
    global connection_monitor_running
    connection_monitor_running = False
    logger.info("Signaled connection monitor to stop")
    return True


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

    # First try to connect
    connection_result = ensure_connection()

    # Start the connection monitor thread
    if connection_result:
        start_connection_monitor()

    return connection_result


def get_relay_states_with_timestamps():
    """Get all relay states with their last change timestamps from Redis"""
    try:
        from db import redis_client
        config = load_config()
        modbus_config = config.get('modbus', {})
        max_channels = int(modbus_config.get('max_channels', 16))

        states = []
        for channel in range(1, max_channels + 1):
            redis_key = f"relay_state:{channel}"
            state_data = redis_client.get(redis_key)

            if state_data:
                try:
                    state_json = json.loads(state_data)
                    states.append(state_json)
                except json.JSONDecodeError:
                    # Handle older format where only state was stored
                    states.append({
                        "channel": channel,
                        "state": int(state_data),
                        "timestamp": None
                    })
            else:
                # No data in Redis, try to read current state
                current_state = read_relay_state(channel)
                states.append({
                    "channel": channel,
                    "state": 1 if current_state else 0 if current_state is not None else None,
                    "timestamp": None
                })

        return states
    except Exception as e:
        logger.error(f"Error getting relay states with timestamps: {e}")
        return None


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