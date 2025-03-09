"""
Modbus Relay Module - Async Version
===================================

This module manages the Modbus relay connection and provides
functions to control relay channels. It supports both pulse and
follower modes, and is compatible with pymodbus 3.8.6.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pymodbus.client.tcp import AsyncModbusTcpClient
import aiohttp
from datetime import datetime
import json
from redis_manager import get_redis, get_pool_stats

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

client = None
config: Dict[str, Any] = {
    "modbus": {
        "ip": "",
        "port": 502,
        "unit_id": 1,
        "max_channels": 16,
        "pulse_seconds": 1.0,
        "enabled": False,
        "follower_mode": False
    }
}

async def load_config() -> Dict[str, Any]:
    from config import load_config as load_config_impl
    return await load_config_impl()

async def get_client() -> AsyncModbusTcpClient:
    global client
    if client is None:
        logger.debug("Creating new AsyncModbusTcpClient instance")
        client = AsyncModbusTcpClient("modbus-proxy", port=1502, timeout=1)
    return client

async def configure_proxy(target_ip: str, target_port: int, retry_count: int = 3) -> bool:
    url = "http://modbus-proxy:5000/api/modbus-proxy/configure"
    data = {"target_ip": target_ip, "target_port": target_port, "enabled": True}
    for attempt in range(retry_count):
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, timeout=timeout) as response:
                    if response.status == 200:
                        logger.info(f"Modbus proxy configured with {target_ip}:{target_port}")
                        return True
                    response_text = await response.text()
                    logger.warning(f"Proxy config failed (attempt {attempt+1}/{retry_count}): Status {response.status} - {response_text}")
                    if attempt < retry_count - 1:
                        wait_time = min(10, 0.5 * (2 ** attempt)) * (0.9 + 0.2 * (hash(datetime.now().microsecond) % 10) / 10)
                        logger.debug(f"Retrying in {wait_time:.2f}s")
                        await asyncio.sleep(wait_time)
        except aiohttp.ClientError as e:
            logger.error(f"Error configuring Modbus proxy (attempt {attempt+1}/{retry_count}): {e}")
            if attempt < retry_count - 1:
                await asyncio.sleep(1.5 * (attempt + 1))
    return False

async def ensure_connection(max_retries: int = 3) -> bool:
    local_config = await load_config()
    config["modbus"] = local_config.get("modbus", {})
    unit_id = config["modbus"].get("unit_id", 1)

    if not config["modbus"].get("enabled", False):
        logger.info("Modbus relay is disabled in configuration")
        return False

    modbus_client = await get_client()

    if modbus_client.connected:
        try:
            result = await modbus_client.read_coils(address=0, count=1, slave=unit_id)
            if result and hasattr(result, "isError") and not result.isError():
                logger.debug("Modbus connection is healthy")
                return True
            logger.warning("Modbus connection test failed, will reset")
            return await reset_connection()
        except Exception as e:
            logger.warning(f"Error testing Modbus connection: {e}")
            return await reset_connection()

    for attempt in range(max_retries):
        try:
            await modbus_client.connect()
            if modbus_client.connected:
                logger.info("Connected to Modbus proxy at modbus-proxy:1502")
                try:
                    redis_client = await get_redis()
                    await redis_client.set("modbus_last_connected", datetime.now().isoformat())
                    await redis_client.set("modbus_connection_status", "connected")
                except Exception as e:
                    logger.error(f"Failed to update Redis: {e}")
                return True
            else:
                logger.error(f"Failed to connect (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = min(10, 1 * (2 ** attempt))
                    logger.debug(f"Retrying in {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
        except Exception as e:
            logger.error(f"Connection failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(1.5 * (attempt + 1))

    try:
        redis_client = await get_redis()
        await redis_client.set("modbus_connection_status", "disconnected")
    except Exception as e:
        logger.error(f"Failed to update Redis status: {e}")
    return False

async def initialize() -> bool:
    try:
        local_config = await load_config()
        config["modbus"] = local_config.get("modbus", {})
        if not config["modbus"].get("enabled", False):
            logger.info("Modbus relay disabled, skipping initialization")
            return False
        redis_client = await get_redis()
        await redis_client.ping()
        stats = await get_pool_stats()
        logger.debug(f"Redis pool stats at Modbus init: {stats}")
        modbus_config = config.get("modbus", {})
        if not modbus_config.get("ip"):
            logger.error("Modbus IP not configured")
            return False
        if await configure_proxy(modbus_config["ip"], modbus_config["port"]):
            if await ensure_connection():
                logger.info(f"Modbus relay initialized to {modbus_config['ip']}:{modbus_config['port']}")
                return True
            logger.error("Failed to connect to Modbus proxy after configuration")
            return False
        logger.error("Failed to configure Modbus proxy")
        return False
    except Exception as e:
        logger.exception(f"Failed to initialize Modbus relay: {e}")
        return False

async def trigger_relay(channel: int, state: bool = True, pulse_seconds: float = None, follower_mode: bool = None, is_test: bool = False) -> bool:
    if not await ensure_connection():
        logger.error("No active connection to Modbus relay")
        if not await reset_connection():
            return False

    local_config = await load_config()
    modbus_config = local_config.get("modbus", {})
    unit_id = modbus_config.get("unit_id", 1)
    max_channels = modbus_config.get("max_channels", 16)
    is_follower_mode = follower_mode if follower_mode is not None else modbus_config.get("follower_mode", False)
    pulse_duration = pulse_seconds if pulse_seconds is not None else modbus_config.get("pulse_seconds", 1.0)

    if not 1 <= channel <= max_channels:
        logger.error(f"Invalid channel {channel}. Must be between 1 and {max_channels}")
        return False

    coil_address = channel - 1
    modbus_client = await get_client()

    try:
        if not modbus_client.connected:
            await modbus_client.connect()
            if not modbus_client.connected:
                logger.error("Failed to connect to Modbus proxy")
                return False

        for attempt in range(3):
            try:
                result = await modbus_client.write_coil(coil_address, state, slave=unit_id)
                if hasattr(result, "isError") and result.isError():
                    logger.error(f"Failed to set relay channel {channel} (attempt {attempt + 1}/3): {result}")
                    if attempt < 2:
                        await asyncio.sleep(0.5)
                        if attempt > 0:
                            await reset_connection()
                    continue
                break
            except Exception as e:
                logger.error(f"Error setting relay (attempt {attempt + 1}/3): {e}")
                if attempt < 2:
                    await asyncio.sleep(0.5)
                    await reset_connection()
        else:
            logger.error(f"All attempts to set relay channel {channel} failed")
            return False

        logger.info(f"Set relay channel {channel} to {'ON' if state else 'OFF'}")

        try:
            redis_client = await get_redis()
            relay_state_data = {
                "state": int(state),
                "timestamp": datetime.now().isoformat(),
                "channel": channel
            }
            await redis_client.set(f"relay_state:{channel}", json.dumps(relay_state_data))
            logger.debug(f"Stored relay state for channel {channel}")
        except Exception as e:
            logger.error(f"Failed to store relay state for channel {channel}: {e}")

        if state and ((not is_follower_mode and pulse_duration) or is_test):
            logger.debug(f"Creating pulse_off task for channel {channel} with {pulse_duration}s")
            pulse_task = asyncio.create_task(pulse_off(channel, pulse_duration))
            def handle_pulse_error(task):
                try:
                    task.result()
                except asyncio.CancelledError:
                    logger.debug(f"Pulse task for channel {channel} cancelled")
                except Exception as e:
                    logger.error(f"Pulse task for channel {channel} failed: {e}")
            pulse_task.add_done_callback(handle_pulse_error)

        return True
    except Exception as e:
        logger.exception(f"Error setting relay channel {channel}: {e}")
        try:
            if asyncio.iscoroutinefunction(modbus_client.close):
                await modbus_client.close()
            else:
                modbus_client.close()
            logger.info("Closed Modbus connection due to error")
        except Exception as e:
            logger.error(f"Error closing connection: {e}")
        return False

async def pulse_off(channel: int, delay: float) -> None:
    try:
        logger.debug(f"Pulse off scheduled for channel {channel} in {delay} seconds")
        await asyncio.sleep(delay)
        result = await trigger_relay(channel, False)
        if result:
            logger.debug(f"Pulsed off relay channel {channel} after {delay} seconds")
        else:
            logger.error(f"Failed to pulse off relay channel {channel}")
    except Exception as e:
        logger.exception(f"Error pulsing off relay channel {channel}: {e}")

async def shutdown_modbus() -> None:
    global client
    if client and client.connected:
        try:
            if asyncio.iscoroutinefunction(client.close):
                await client.close()
            else:
                client.close()
            logger.info("Modbus client connection closed gracefully")
        except Exception as e:
            logger.error(f"Error during Modbus client shutdown: {e}")
    client = None

async def test_channels(channel_count: int = None) -> Dict[str, Any]:
    local_config = await load_config()
    modbus_config = local_config.get("modbus", {})
    if not modbus_config.get("enabled", False):
        return {"status": "error", "message": "Modbus relay is disabled in configuration", "results": []}
    if channel_count is None:
        channel_count = modbus_config.get("max_channels", 16)
    if not await initialize():
        return {"status": "error", "message": "Failed to initialize Modbus connection", "results": []}
    results = []
    success_count = 0
    for channel in range(1, channel_count + 1):
        logger.info(f"Testing relay channel {channel}")
        try:
            result = await trigger_relay(channel, True, 0.2, is_test=True)
            results.append({
                "channel": channel,
                "success": result,
                "message": f"Channel {channel} {'activated successfully' if result else 'failed to activate'}"
            })
            if result:
                success_count += 1
            await asyncio.sleep(0.3)
        except Exception as e:
            logger.error(f"Error testing channel {channel}: {e}")
            results.append({"channel": channel, "success": False, "message": f"Error: {str(e)}"})
    return {
        "status": "success" if success_count == channel_count else "partial" if success_count > 0 else "error",
        "message": f"{success_count}/{channel_count} channels tested successfully",
        "results": results
    }

async def reset_connection() -> bool:
    global client
    logger.info("Forcibly resetting Modbus client connection")
    if client is not None:
        try:
            if client.connected:
                if asyncio.iscoroutinefunction(client.close):
                    await client.close()
                else:
                    client.close()
                logger.debug("Closed existing Modbus connection")
        except Exception as e:
            logger.error(f"Error closing existing connection: {e}")
    try:
        client = AsyncModbusTcpClient("modbus-proxy", port=1502, timeout=1)
        await client.connect()
        if client.connected:
            logger.info("Successfully reset and reconnected Modbus client")
            try:
                redis_client = await get_redis()
                await redis_client.set("modbus_last_connected", datetime.now().isoformat())
                await redis_client.set("modbus_connection_status", "connected")
            except Exception as e:
                logger.error(f"Failed to update Redis after reset: {e}")
            return True
        else:
            logger.error("Failed to reconnect after reset")
            client = None
            return False
    except Exception as e:
        logger.error(f"Error resetting Modbus connection: {e}")
        client = None
        return False

async def main():
    try:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        logger.info("Testing Modbus relay module")
        if not await initialize():
            logger.error("Failed to initialize Modbus relay, exiting")
            return
        logger.info("Testing relay channel 1 with a 1-second pulse")
        await trigger_relay(1, True, 1.0)
        await asyncio.sleep(2)
        logger.info("Testing follower mode ON for channel 2")
        await trigger_relay(2, True, follower_mode=True)
        await asyncio.sleep(2)
        logger.info("Testing follower mode OFF for channel 2")
        await trigger_relay(2, False, follower_mode=True)
        await asyncio.sleep(1)
        logger.info("Running test on all channels")
        results = await test_channels(8)
        logger.info(f"Test results: {json.dumps(results, indent=2)}")
    except Exception as e:
        logger.exception(f"Main execution failed: {e}")
    finally:
        await shutdown_modbus()

if __name__ == "__main__":
    asyncio.run(main())