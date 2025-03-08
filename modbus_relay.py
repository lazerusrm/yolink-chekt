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
    """Ensures that we have a valid connection to the Modbus relay."""
    global client, connected

    # Check if we already have a connection
    if client and connected:
        try:
            # Verify connection is still active by reading a coil
            result = client.read_coils(0, 1)
            if hasattr(result, 'function_code') and not result.isError():
                return True
        except Exception:
            # If we can't read coils, connection is bad
            connected = False
            logger.warning("Modbus connection validation failed, will reconnect")

    config = load_config()
    modbus_config = config.get('modbus', {})

    if not modbus_config.get('ip'):
        logger.warning("Modbus relay IP not configured")
        connected = False
        return False

    try:
        # Close any existing connection
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing existing Modbus connection: {e}")

        # Create a new connection
        client = ModbusTcpClient(
            host=modbus_config.get('ip'),
            port=modbus_config.get('port', 502),
            timeout=5
        )

        # Try to connect
        connected = client.connect()
        if connected:
            logger.info(
                f"Successfully connected to Modbus relay at {modbus_config.get('ip')}:{modbus_config.get('port', 502)}")

            # Try to read first coil to validate connection
            try:
                result = client.read_coils(0, 1)
                if not hasattr(result, 'function_code') or result.isError():
                    logger.warning("Modbus connection succeeded but read test failed")
                    connected = False
            except Exception as e:
                logger.warning(f"Modbus connection succeeded but read test failed: {e}")
                connected = False

        else:
            logger.error(
                f"Failed to connect to Modbus relay at {modbus_config.get('ip')}:{modbus_config.get('port', 502)}")

        return connected
    except Exception as e:
        logger.error(f"Error connecting to Modbus relay: {e}")
        connected = False
        return False


def trigger_relay(channel, state=True, pulse_seconds=None, follower_mode=None):
    """
    Trigger a relay channel with improved error handling.

    Args:
        channel (int): The relay channel number (1-16)
        state (bool): True to turn relay on, False to turn it off
        pulse_seconds (float, optional): If provided, relay will turn on for this time then turn off
        follower_mode (bool, optional): Override global follower_mode setting

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check connection
        if not ensure_connection():
            logger.error("Cannot trigger relay: No connection to Modbus relay")
            return False

        config = load_config()
        modbus_config = config.get('modbus', {})

        # Get unit ID with validation
        try:
            unit_id = int(modbus_config.get('unit_id', 1))
        except (ValueError, TypeError):
            unit_id = 1
            logger.warning(f"Invalid unit_id in config, using default: 1")

        # Determine if we're using follower mode
        if follower_mode is None:
            follower_mode = modbus_config.get('follower_mode', False)

        # Validate channel number
        try:
            max_channels = int(modbus_config.get('max_channels', 16))
        except (ValueError, TypeError):
            max_channels = 16
            logger.warning(f"Invalid max_channels in config, using default: 16")

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

        try:
            # Write to coil
            logger.info(f"Setting relay channel {channel} to {'ON' if state else 'OFF'}")
            result = client.write_coil(coil_address, state, unit=unit_id)

            if hasattr(result, 'function_code') and not result.isError():
                logger.info(f"Successfully set relay channel {channel} to {'ON' if state else 'OFF'}")

                # If in follower mode, we don't pulse - the relay follows sensor state
                if not follower_mode:
                    # If pulse_seconds is specified and we're turning the relay on,
                    # schedule it to turn off after the specified time
                    if pulse_seconds and state:
                        def turn_off_later():
                            try:
                                time.sleep(pulse_seconds)
                                logger.info(f"Turning off relay channel {channel} after {pulse_seconds} seconds pulse")
                                trigger_relay(channel, False)
                            except Exception as e:
                                logger.error(f"Error in turn_off_later for channel {channel}: {e}")

                        # Start a thread to turn off the relay after the specified time
                        threading.Thread(target=turn_off_later, daemon=True).start()

                # Store the current relay state in Redis for reference
                try:
                    from db import redis_client
                    redis_client.set(f"relay_state:{channel}", "1" if state else "0")
                except Exception as e:
                    logger.error(f"Failed to store relay state in Redis: {e}")

                return True
            else:
                logger.error(f"Failed to set relay channel {channel}: {result}")
                return False
        except ConnectionException:
            logger.error("Connection to Modbus relay lost")
            connected = False
            return False
        except ModbusException as e:
            logger.error(f"Modbus error when setting relay channel {channel}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error when setting relay channel {channel}: {e}")
            return False
    except Exception as e:
        logger.error(f"Critical error in trigger_relay for channel {channel}: {e}")
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