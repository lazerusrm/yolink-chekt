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

# Import the Redis manager
from redis_manager import get_redis

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
        # Register new connection
        connection = websocket._get_current_object()
        active_connections.add(connection)
        logger.info(f"New WebSocket connection established. Active connections: {len(active_connections)}")

        # Send current data if available
        if last_broadcast_data:
            await connection.send(json.dumps(last_broadcast_data))

        # Handle connection
        try:
            # Keep connection alive until client disconnects
            while True:
                # This is mostly to handle disconnections
                data = await connection.receive()
                # We don't expect client messages, but could process them here
        except asyncio.CancelledError:
            # Handle graceful shutdown
            logger.info("WebSocket connection cancelled (shutdown)")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            # Remove the connection when done
            active_connections.discard(connection)
            logger.info(f"WebSocket connection closed. Active connections: {len(active_connections)}")


async def broadcast_sensor_update(sensors: List[Dict[str, Any]]) -> None:
    """
    Broadcast sensor updates to all connected WebSocket clients.

    Args:
        sensors (List[Dict[str, Any]]): List of sensor data to broadcast
    """
    global last_broadcast_data

    # Create the message payload
    payload = {
        "type": "sensors-update",
        "sensors": sensors,
        "timestamp": asyncio.get_event_loop().time()
    }

    # Store the payload for sending to new connections
    last_broadcast_data = payload

    # Convert to JSON string
    message = json.dumps(payload)

    # Send to all active connections
    if active_connections:
        send_tasks = []
        for connection in list(active_connections):
            try:
                send_tasks.append(connection.send(message))
            except Exception as e:
                logger.error(f"Error preparing to send to WebSocket: {e}")
                active_connections.discard(connection)

        # Execute all sends concurrently
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

    # Add the task to app context for proper cleanup
    @app.before_serving
    async def setup_broadcast_task():
        """Set up the broadcast task before serving."""
        app.broadcast_task = asyncio.create_task(broadcast_loop(interval))
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


async def broadcast_loop(interval: int) -> None:
    """
    Background loop that periodically broadcasts device updates.

    Args:
        interval (int): Update interval in seconds
    """
    while True:
        try:
            # Get all devices from Redis
            from device_manager import get_all_devices
            redis_client = await get_redis()
            devices = await get_all_devices(redis_client)

            # Broadcast update if there are devices and WebSocket connections
            if devices and active_connections:
                await broadcast_sensor_update(devices)
                logger.debug(f"Broadcast device update to {len(active_connections)} connections")
        except asyncio.CancelledError:
            # Handle graceful shutdown
            logger.info("Device broadcaster task cancelled")
            break
        except Exception as e:
            logger.error(f"Error in device broadcast loop: {e}")

        # Wait for next update interval
        await asyncio.sleep(interval)


# Sample implementation for app.py integration
def init_websocket(app: Quart) -> None:
    """
    Initialize WebSocket functionality for the application.

    Call this function from app.py to set up WebSocket support.

    Args:
        app (Quart): The Quart application
    """
    # Set up WebSocket routes
    asyncio.run(setup_websocket_routes(app))

    # Start background broadcaster with 10-second interval
    asyncio.run(start_device_broadcaster(app, 10))

    logger.info("WebSocket functionality initialized")