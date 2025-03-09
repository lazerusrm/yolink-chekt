"""
WebSocket Handler for YoLink Integration - Async Version
======================================================

This module provides WebSocket integration for the YoLink dashboard,
enabling real-time updates of device status.
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Set, Optional
import aiohttp
from quart import Quart, websocket
from redis.asyncio import Redis

# Logging setup
logger = logging.getLogger(__name__)

# Active WebSocket connections
active_connections: Set[Any] = set()

# Last broadcast data (for immediate sending to new connections)
last_broadcast_data: Optional[Dict[str, Any]] = None


async def setup_websocket_routes(app: Quart) -> None:
    """
    Set up WebSocket routes for the application.

    Args:
        app (Quart): The Quart application
    """

    @app.websocket('/ws')
    async def ws():
        """WebSocket endpoint for real-time sensor updates."""
        connection = websocket._get_current_object()
        active_connections.add(connection)
        logger.info(f"New WebSocket connection established. Active connections: {len(active_connections)}")

        if last_broadcast_data:
            await connection.send(json.dumps(last_broadcast_data))

        try:
            while True:
                await connection.receive()
        except asyncio.CancelledError:
            logger.info("WebSocket connection cancelled (shutdown)")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            active_connections.discard(connection)
            logger.info(f"WebSocket connection closed. Active connections: {len(active_connections)}")


async def broadcast_sensor_update(sensors: List[Dict[str, Any]]) -> None:
    """
    Broadcast sensor updates to all connected WebSocket clients.

    Args:
        sensors (List[Dict[str, Any]]): List of sensor data to broadcast
    """
    global last_broadcast_data

    payload = {
        "type": "sensors-update",
        "sensors": sensors,
        "timestamp": asyncio.get_event_loop().time()
    }
    last_broadcast_data = payload
    message = json.dumps(payload)

    if active_connections:
        send_tasks = []
        for connection in list(active_connections):
            try:
                send_tasks.append(connection.send(message))
            except Exception as e:
                logger.error(f"Error preparing to send to WebSocket: {e}")
                active_connections.discard(connection)

        if send_tasks:
            results = await asyncio.gather(*send_tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to send to WebSocket: {result}")


async def start_device_broadcaster(app: Quart, interval: int = 15) -> None:
    """
    Start a background task to periodically broadcast device updates.

    Args:
        app (Quart): The Quart application
        interval (int): Update interval in seconds
    """
    @app.before_serving
    async def setup_broadcast_task():
        """Set up the broadcast task before serving."""
        from redis_manager import get_redis
        redis_client = await get_redis()  # Single client for the loop
        app.broadcast_task = asyncio.create_task(broadcast_loop(redis_client, interval))
        app.bg_tasks.append(app.broadcast_task)

    @app.after_serving
    async def cleanup_broadcast_task():
        """Clean up the broadcast task after serving."""
        if hasattr(app, 'broadcast_task') and not app.broadcast_task.done():
            app.broadcast_task.cancel()
            try:
                await app.broadcast_task
            except asyncio.CancelledError:
                pass


async def broadcast_loop(redis_client: Redis, interval: int) -> None:
    """
    Background loop that periodically broadcasts device updates using a single Redis client.

    Args:
        redis_client (Redis): Shared Redis client instance
        interval (int): Update interval in seconds
    """
    while True:
        try:
            from device_manager import get_all_devices
            devices = await get_all_devices()
            if devices and active_connections:
                await broadcast_sensor_update(devices)
                logger.debug(f"Broadcast device update to {len(active_connections)} connections")
            from redis_manager import get_pool_stats  # Already correct, just ensuring
            stats = await get_pool_stats()
            logger.debug(f"Redis pool stats during broadcast: {stats}")
        except asyncio.CancelledError:
            logger.info("Device broadcaster task cancelled")
            break
        except Exception as e:
            logger.error(f"Error in device broadcast loop: {e}")
        await asyncio.sleep(interval)


def init_websocket(app: Quart) -> None:
    """
    Initialize WebSocket functionality for the application.

    Args:
        app (Quart): The Quart application
    """
    asyncio.run(setup_websocket_routes(app))
    asyncio.run(start_device_broadcaster(app, 10))
    logger.info("WebSocket functionality initialized")