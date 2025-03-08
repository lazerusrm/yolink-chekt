import logging
from pymodbus.client import ModbusTcpClient
import time
import threading
from pymodbus.exceptions import ModbusException, ConnectionException
from config import load_config

logger = logging.getLogger(__name__)

# Global client to reuse connection
client = None
connected = False


def ensure_connection():
    """Ensures that we have a valid connection to the Modbus relay with improved Docker networking handling."""
    global client, connected

    config = load_config()
    modbus_config = config.get('modbus', {})

    # Check if Modbus is enabled
    if not modbus_config.get('enabled', False):
        logger.info("Modbus relay not enabled in configuration")
        connected = False
        return False

    # Get IP with validation
    modbus_ip = modbus_config.get('ip')
    if not modbus_ip or not modbus_ip.strip():
        logger.warning("Modbus relay IP not configured")
        connected = False
        return False

    # Set default port
    modbus_port = int(modbus_config.get('port', 502))

    # Check if current connection is still valid
    if client and connected:
        try:
            # Test with a simple read
            result = client.read_coils(0, 1)
            if result and not result.isError():
                return True
        except Exception:
            # Connection lost, will reconnect
            logger.info("Modbus connection test failed, reconnecting...")
            connected = False

    # Close existing connection if any
    if client:
        try:
            client.close()
        except Exception:
            pass

    # Connect with retry logic
    retry_count = 3
    retry_delay = 1  # seconds

    for attempt in range(retry_count):
        try:
            logger.info(
                f"Connecting to Modbus relay at {modbus_ip}:{modbus_port} (attempt {attempt + 1}/{retry_count})")

            # Create client with longer timeout for Docker networking
            client = ModbusTcpClient(
                host=modbus_ip,
                port=modbus_port,
                timeout=5 * (attempt + 1)  # Increase timeout with each retry
            )

            # Connect
            connected = client.connect()
            if not connected:
                logger.warning(f"Failed to connect on attempt {attempt + 1}")
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                continue

            # Verify connection with read test
            logger.info(f"Connected, verifying connection with read test")
            result = client.read_coils(0, 1)
            if not result or result.isError():
                logger.warning(f"Connected but read test failed, error: {result if result else 'None'}")
                connected = False
                client.close()
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                continue

            # Success!
            logger.info(f"Successfully connected and verified Modbus relay at {modbus_ip}:{modbus_port}")
            return True

        except ConnectionException as e:
            logger.error(f"Modbus connection error on attempt {attempt + 1}: {e}")
            connected = False
            if attempt < retry_count - 1:
                time.sleep(retry_delay)
                retry_delay *= 2
        except Exception as e:
            logger.error(f"Unexpected error on connection attempt {attempt + 1}: {e}")
            connected = False
            if attempt < retry_count - 1:
                time.sleep(retry_delay)
                retry_delay *= 2

    # All attempts failed
    logger.error(f"Failed to connect to Modbus relay at {modbus_ip}:{modbus_port} after {retry_count} attempts")
    return False


def trigger_relay(channel, state=True, pulse_seconds=None, follower_mode=None):
    """
    Trigger a relay channel with improved reliability for Docker environments.

    Args:
        channel (int): The relay channel number (1-16)
        state (bool): True to turn relay on, False to turn it off
        pulse_seconds (float, optional): If provided, relay will turn on for this time then turn off
        follower_mode (bool, optional): Override global follower_mode setting

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure connection with retries
        connection_attempts = 2
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

        # Get unit ID with validation
        try:
            unit_id = int(modbus_config.get('unit_id', 1))
        except (ValueError, TypeError):
            unit_id = 1
            logger.warning(f"Invalid unit_id in config, using default: 1")

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
                result = client.write_coil(coil_address, state, unit=unit_id)

                if not result or result.isError():
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
                if attempt < write_attempts - 1:
                    time.sleep(1)

        # All attempts failed
        logger.error(f"Failed to set relay channel {channel} after {write_attempts} attempts")
        return False

    except Exception as e:
        logger.error(f"Critical error in trigger_relay: {e}")
        return False


def read_relay_state(channel):
    """
    Read the current state of a relay channel.

    Args:
        channel (int): The relay channel number (1-16)

    Returns:
        bool or None: True if relay is on, False if off, None if error
    """
    if not ensure_connection():
        logger.error("Cannot read relay state: No connection to Modbus relay")
        return None

    config = load_config()
    modbus_config = config.get('modbus', {})
    unit_id = modbus_config.get('unit_id', 1)

    # Validate channel number
    max_channels = modbus_config.get('max_channels', 16)
    if not 1 <= channel <= max_channels:
        logger.error(f"Invalid relay channel: {channel}. Must be between 1 and {max_channels}")
        return None

    # Adjust channel number for zero-based addressing in Modbus
    coil_address = channel - 1

    try:
        # Read from coil
        result = client.read_coils(coil_address, 1, unit=unit_id)

        if hasattr(result, 'function_code') and not result.isError():
            state = result.bits[0]
            logger.debug(f"Relay channel {channel} is {'ON' if state else 'OFF'}")
            return state
        else:
            logger.error(f"Failed to read relay channel {channel}: {result}")
            return None
    except ConnectionException:
        logger.error("Connection to Modbus relay lost")
        connected = False
        return None
    except ModbusException as e:
        logger.error(f"Modbus error when reading relay channel {channel}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when reading relay channel {channel}: {e}")
        return None


def read_all_relay_states():
    """
    Read the state of all relay channels.

    Returns:
        list or None: List of booleans representing relay states, None if error
    """
    if not ensure_connection():
        logger.error("Cannot read relay states: No connection to Modbus relay")
        return None

    config = load_config()
    modbus_config = config.get('modbus', {})
    unit_id = modbus_config.get('unit_id', 1)
    max_channels = modbus_config.get('max_channels', 16)

    try:
        # Read from coils
        result = client.read_coils(0, max_channels, unit=unit_id)

        if hasattr(result, 'function_code') and not result.isError():
            states = list(result.bits)[:max_channels]  # Limit to actual number of channels
            logger.debug(f"All relay states: {states}")
            return states
        else:
            logger.error(f"Failed to read all relay states: {result}")
            return None
    except ConnectionException:
        logger.error("Connection to Modbus relay lost")
        connected = False
        return None
    except ModbusException as e:
        logger.error(f"Modbus error when reading all relay states: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when reading all relay states: {e}")
        return None


def initialize():
    """Initialize the Modbus relay connection."""
    return ensure_connection()


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Test connection
    initialize()

    # Test triggering relays
    for i in range(1, 9):
        trigger_relay(i, True)
        import time

        time.sleep(0.5)
        trigger_relay(i, False)
        time.sleep(0.5)