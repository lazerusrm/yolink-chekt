"""
WebSocket Handler for YoLink Integration - Async Version with HTTPS Support
==============================================================

This module provides a robust WebSocket integration for the YoLink dashboard,
enabling secure real-time device status updates with comprehensive client tracking.
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import aiohttp
from quart import Quart, websocket, request
from redis.asyncio import Redis

# Configure logging
logger = logging.getLogger(__name__)

# Global state management
class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        self.last_broadcast_data: Optional[Dict[str, Any]] = None

    def get_connection_count(self) -> int:
        return len(self.active_connections)

ws_manager = WebSocketManager()

async def setup_websocket_routes(app: Quart) -> None:
    """
    Configure WebSocket routes for the Quart application.

    Args:
        app (Quart): The Quart application instance
    """
    @app.websocket('/ws')
    async def ws_handler():
        """Handle WebSocket connections with client tracking and error handling."""
        connection = websocket._get_current_object()
        client_id = str(uuid.uuid4())

        # Create client metadata
        client_info = {
            "id": client_id,
            "ip": request.remote_addr,
            "port": request.environ.get('REMOTE_PORT', 'unknown'),
            "connection_time": datetime.now().isoformat(),
            "connection": connection,
            "messages_sent": 0,
            "last_active": datetime.now().timestamp()
        }
        ws_manager.active_connections[client_id] = client_info

        # Determine connection protocol
        is_secure = request.scheme == 'https' or request.headers.get('X-Forwarded-Proto') == 'https'
        protocol = "WSS" if is_secure else "WS"
        client_str = f"{client_info['ip']}:{client_info['port']}"
        logger.info(f"New {protocol} connection from {client_str}. Total: {ws_manager.get_connection_count()}")

        # Send last known state to new connection
        if ws_manager.last_broadcast_data:
            try:
                await connection.send(json.dumps(ws_manager.last_broadcast_data))
                client_info["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Failed to send initial state to {client_str}: {e}")

        try:
            while True:
                # Keep connection alive with heartbeat
                data = await asyncio.wait_for(connection.receive(), timeout=30.0)
                client_info["last_active"] = datetime.now().timestamp()
                logger.debug(f"Received heartbeat from {client_str}")
        except asyncio.TimeoutError:
            logger.warning(f"Connection timeout for {client_str}")
        except asyncio.CancelledError:
            logger.info(f"WebSocket connection cancelled for {client_str}")
        except Exception as e:
            logger.error(f"WebSocket error for {client_str}: {e}")
        finally:
            del ws_manager.active_connections[client_id]
            logger.info(f"Connection closed for {client_str}. Total: {ws_manager.get_connection_count()}")

async def broadcast_sensor_update(sensors: List[Dict[str, Any]]) -> None:
    """
    Broadcast sensor updates to all connected WebSocket clients.

    Args:
        sensors (List[Dict[str, Any]]): List of sensor data to broadcast
    """
    payload = {
        "type": "sensors-update",
        "sensors": sensors,
        "timestamp": datetime.now().isoformat(),
        "connection_count": ws_manager.get_connection_count()
    }
    ws_manager.last_broadcast_data = payload
    message = json.dumps(payload)

    if not ws_manager.active_connections:
        logger.debug("No active connections for broadcast")
        return

    async def send_to_client(client_id: str, client_info: Dict[str, Any]) -> None:
        try:
            await client_info["connection"].send(message)
            client_info["messages_sent"] += 1
            client_info["last_active"] = datetime.now().timestamp()
        except Exception as e:
            logger.error(f"Failed to send to client {client_id}: {e}")
            del ws_manager.active_connections[client_id]

    tasks = [
        send_to_client(client_id, client_info)
        for client_id, client_info in ws_manager.active_connections.items()
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

async def broadcast_loop(redis_client: Redis, interval: int) -> None:
    """
    Periodic broadcast loop for device updates.

    Args:
        redis_client (Redis): Redis client instance
        interval (int): Broadcast interval in seconds
    """
    while True:
        try:
            from device_manager import get_all_devices
            devices = await get_all_devices()

            if devices and ws_manager.active_connections:
                await broadcast_sensor_update(devices)
                logger.debug(f"Broadcast to {ws_manager.get_connection_count()} clients")

            from redis_manager import get_pool_stats
            stats = await get_pool_stats()
            logger.debug(f"Redis stats: {stats}")

        except asyncio.CancelledError:
            logger.info("Broadcast loop cancelled")
            break
        except Exception as e:
            logger.error(f"Broadcast loop error: {e}")
        await asyncio.sleep(interval)

async def setup_broadcast_task(app: Quart, interval: int = 10) -> None:
    """
    Configure and manage the broadcast background task.

    Args:
        app (Quart): Quart application instance
        interval (int): Broadcast interval in seconds
    """
    async def start_task():
        from redis_manager import get_redis
        redis_client = await get_redis()
        app.broadcast_task = asyncio.create_task(broadcast_loop(redis_client, interval))

    async def cleanup_task():
        if hasattr(app, 'broadcast_task') and not app.broadcast_task.done():
            app.broadcast_task.cancel()
            try:
                await app.broadcast_task
            except asyncio.CancelledError:
                pass

    app.before_serving(start_task)
    app.after_serving(cleanup_task)

def init_websocket(app: Quart, broadcast_interval: int = 10) -> None:
    """
    Initialize WebSocket functionality for the application.

    Args:
        app (Quart): Quart application instance
        broadcast_interval (int): Interval for device broadcasts in seconds
    """
    # Setup routes and broadcaster
    asyncio.run(setup_websocket_routes(app))
    asyncio.run(setup_broadcast_task(app, broadcast_interval))

    # Log SSL configuration
    ssl_enabled = os.environ.get('DISABLE_HTTPS', 'false').lower() != 'true'
    protocol = "WSS" if ssl_enabled else "WS"
    logger.info(f"WebSocket initialized with {protocol} support")