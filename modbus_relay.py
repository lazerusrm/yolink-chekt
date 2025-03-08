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

    if client and connected:
        return True

    config = load_config()
    modbus_config = config.get('modbus', {})

    if not modbus_config.get('ip'):
        logger.warning("Modbus relay IP not configured")
        connected = False
        return False

    try:
        # Close any existing connection
        if client:
            client.close()

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
        else:
            logger.error(
                f"Failed to connect to Modbus relay at {modbus_config.get('ip')}:{modbus_config.get('port', 502)}")

        return connected
    except Exception as e:
        logger.error(f"Error connecting to Modbus relay: {e}")
        connected = False
        return False


def trigger_relay(channel, state=True, pulse_seconds=None):
    """
    Trigger a relay channel.

    Args:
        channel (int): The relay channel number (1-16)
        state (bool): True to turn relay on, False to turn it off
        pulse_seconds (int, optional): If provided, the relay will turn on for this many seconds and then turn off
                                       For this to work, you must call this function with state=True

    Returns:
        bool: True if successful, False otherwise
    """
    if not ensure_connection():
        logger.error("Cannot trigger relay: No connection to Modbus relay")
        return False

    config = load_config()
    modbus_config = config.get('modbus', {})
    unit_id = modbus_config.get('unit_id', 1)  # Default to 1 if not specified

    # Validate channel number
    max_channels = modbus_config.get('max_channels', 16)
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

            # If pulse_seconds is specified and we're turning the relay on,
            # schedule it to turn off after the specified time
            if pulse_seconds and state:
                import threading
                import time

                def turn_off_later():
                    time.sleep(pulse_seconds)
                    logger.info(f"Turning off relay channel {channel} after {pulse_seconds} seconds pulse")
                    trigger_relay(channel, False)

                # Start a thread to turn off the relay after the specified time
                threading.Thread(target=turn_off_later, daemon=True).start()

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