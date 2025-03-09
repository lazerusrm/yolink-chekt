"""
Redis Connection Manager - Shared Redis Client Pool (Enhanced)
=============================================================

Provides a centralized Redis connection manager with a shared connection pool,
reconnection logic, and robust resource management for async applications.
"""

import os
import logging
import asyncio
from typing import Optional, Dict, Any
from redis.asyncio import Redis, ConnectionPool
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global connection pool and client
_pool: Optional[ConnectionPool] = None
_redis_client: Optional[Redis] = None
_lock = asyncio.Lock()
_initializing = False  # Track initialization state


async def get_redis() -> Redis:
    """
    Get or create a Redis client using the shared connection pool.

    Returns:
        Redis: An async Redis client instance

    Raises:
        ConnectionError: If connection to Redis fails
    """
    global _redis_client, _pool, _initializing

    async with _lock:
        if _redis_client is None or not await is_client_alive(_redis_client):
            if _pool is None or _pool.disconnected:
                logger.debug(f"Creating new Redis connection pool: host={_config['host']}, port={_config['port']}, max_connections={_config['max_connections']}")
                _pool = ConnectionPool(
                    host=_config["host"],
                    port=_config["port"],
                    db=_config["db"],
                    decode_responses=_config["decode_responses"],
                    max_connections=_config["max_connections"]
                )

            _initializing = True
            _redis_client = Redis(connection_pool=_pool)
            try:
                logger.debug("Attempting Redis ping")
                await _redis_client.ping()
                logger.info(f"Connected to Redis at {_config['host']}:{_config['port']}, db={_config['db']}")
                stats = await get_pool_stats()
                logger.debug(f"Pool stats after connection: {stats}")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}", exc_info=True)
                _redis_client = None
                _initializing = False
                raise ConnectionError(f"Redis connection failed: {e}")
            finally:
                _initializing = False
        else:
            logger.debug("Reusing existing Redis client")
            stats = await get_pool_stats()
            logger.debug(f"Pool stats before returning client: {stats}")

        # Wait if still initializing
        if _initializing:
            logger.debug("Waiting for Redis initialization to complete")
            await asyncio.sleep(0.1)  # Small delay to avoid race

    return _redis_client


async def is_client_alive(client: Redis) -> bool:
    """
    Check if the Redis client is still alive.

    Args:
        client (Redis): The Redis client to check

    Returns:
        bool: True if alive, False otherwise
    """
    try:
        await client.ping()
        return True
    except Exception:
        return False


async def ensure_connection(max_retries: int = 5, backoff_base: float = 1.5) -> bool:
    """
    Ensure a Redis connection is established with exponential backoff.

    Args:
        max_retries (int): Maximum number of connection attempts (default: 5)
        backoff_base (float): Base for exponential backoff (default: 1.5)

    Returns:
        bool: True if connected, False if all retries fail
    """
    global _redis_client

    for attempt in range(max_retries):
        try:
            client = await get_redis()
            await client.ping()
            if attempt > 0:
                logger.info(f"Reconnected to Redis after {attempt + 1} attempts")
            return True
        except Exception as e:
            wait_time = min(30, backoff_base ** attempt)
            logger.warning(
                f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}. "
                f"Retrying in {wait_time:.1f}s"
            )
            if attempt < max_retries - 1:
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts")
                _redis_client = None
                return False
    return False


async def update_config(new_config: Dict[str, Any]) -> bool:
    """
    Update Redis configuration and re-establish the connection.

    Args:
        new_config (Dict[str, Any]): New configuration values to update

    Returns:
        bool: True if update and reconnection succeed, False otherwise
    """
    global _config, _redis_client, _pool

    async with _lock:
        try:
            _config.update(new_config)
            logger.info(f"Updated Redis config: {json.dumps(_config, indent=2)}")

            if _redis_client is not None:
                await _redis_client.close()
                _redis_client = None
            if _pool is not None:
                await _pool.disconnect()
                _pool = None

            await get_redis()
            logger.info("Redis connection re-established with updated config")
            return True
        except Exception as e:
            logger.error(f"Failed to update Redis config and reconnect: {e}")
            return False


async def close() -> None:
    """
    Close Redis connections and clean up resources gracefully.
    """
    global _redis_client, _pool

    async with _lock:
        if _redis_client is not None:
            try:
                await _redis_client.close()
                logger.info("Redis client closed successfully")
            except Exception as e:
                logger.error(f"Error closing Redis client: {e}")
            finally:
                _redis_client = None

        if _pool is not None:
            try:
                await _pool.disconnect()
                logger.info("Redis connection pool disconnected successfully")
            except Exception as e:
                logger.error(f"Error disconnecting Redis pool: {e}")
            finally:
                _pool = None


I
'll analyze the codebase and provide insights and recommendations based on the requirements.txt versions. Looking at your YoLink to CHEKT integration system, I can see it'
s
a
Python - based
application
that
connects
YoLink
smart
sensors
to
alarm
systems
using
various
protocols.
Architecture
Overview
Your
system
connects
several
components:

YoLink
sensors
via
MQTT
CHEKT
alarm
system
integration
Modbus
relay
support
SIA
protocol
integration
Redis
for data storage
    WebSocket
    for real - time updates
        A
    web
    dashboard
    with authentication

Version
Analysis
Looking
at
your
requirements.txt:
Copywerkzeug >= 3.0
.3
PyYAML >= 6.0
aiohttp >= 3.8
.5
APScheduler >= 3.10
.4
pyotp >= 2.6
.0
qrcode[pil] >= 7.3
pytz
cryptography
redis >= 5.0
.3
python - dotenv
psutil
pymodbus >= 3.8
.6
quart == 0.20
.0
quart - auth == 0.11
.0
quart - bcrypt >= 0.0
.9
aiomqtt >= 1.0
.0
hypercorn >= 0.17
.3
You
're using Quart 0.20.0, which is specifically pinned, along with modern versions of Redis (5.0.3+) and pymodbus (3.8.6+). This indicates a modern async-based architecture.
Code
Quality
Analysis and Recommendations

Redis
Connection
Management:
You
've created a centralized redis_manager.py which is excellent. This avoids connection pool fragmentation.
Async
Patterns:
Your
codebase
makes
good
use
of
asyncio
patterns
with proper error handling and resource management.
Security:
You
have
TOTP
2
FA, secure
password
storage, and HTTPS
support, which
are
all
good
security
practices.
MQTT
Reliability:
Your
YoLink
MQTT
client
has
robust
reconnection
logic and error
handling.
Code
Organization:
The
modular
structure
separating
config, device
management, mappings, etc. is well - thought - out.

Specific
Recommendations

Streamlined
Configuration
Flow:
The
Docker
setup
for nginx, Redis, and other services looks good, but I notice some potential HTTPS handling issues.
Redis
Connection
Pool
Optimization:
Your
Redis
connection
pooling
could
be
improved
for better resource utilization:

pythonCopy  # In redis_manager.py


async def get_pool_stats() -> Dict[str, int]:
    """
    Get current connection pool statistics with better accuracy.
    """
    global _pool
    if _pool is None:
        return {"total": 0, "in_use": 0, "available": 0}

    # More accurate count of in-use connections
    in_use = len(_pool._in_use_connections)
    total = _pool.max_connections

    return {
        "total": total,
        "in_use": in_use,
        "available": total - in_use,
        "usage_percent": round(in_use * 100 / total, 1) if total else 0
    }

    # Add monitoring of connection creation/closing
    current_time = time.time()
    if not hasattr(_pool, '_last_stats_time'):
        _pool._last_stats_time = current_time
        _pool._connections_created_since_last = 0
        _pool._connections_closed_since_last = 0

    # Reset counters periodically
    if current_time - _pool._last_stats_time > 60:  # Reset every minute
        _pool._connections_created_since_last = 0
        _pool._connections_closed_since_last = 0
        _pool._last_stats_time = current_time

    return {
        "total": total,
        "in_use": in_use,
        "available": total - in_use,
        "created_last_minute": getattr(_pool, '_connections_created_since_last', 0),
        "closed_last_minute": getattr(_pool, '_connections_closed_since_last', 0)
    }


# Configuration with environment variable fallbacks (moved to bottom to avoid reference before assignment)
_config: Dict[str, Any] = {
    "host": os.getenv("REDIS_HOST", "redis"),
    "port": int(os.getenv("REDIS_PORT", 6379)),
    "db": int(os.getenv("REDIS_DB", 0)),
    "decode_responses": True,
    "max_connections": int(os.getenv("REDIS_MAX_CONNECTIONS", 200))
}


if __name__ == "__main__":
    async def test_redis_manager():
        """Test the Redis manager standalone."""
        logging.basicConfig(level=logging.DEBUG)
        try:
            redis = await get_redis()
            await redis.set("test_key", "test_value")
            value = await redis.get("test_key")
            print(f"Set and retrieved test value: {value}")

            connected = await ensure_connection(max_retries=3, backoff_base=1.0)
            print(f"Ensure connection result: {connected}")

            new_config = {"port": 6379, "max_connections": 20}
            updated = await update_config(new_config)
            print(f"Config update result: {updated}")

            await redis.set("post_update_key", "updated")
            print(f"Post-update value: {await redis.get('post_update_key')}")

            stats = await get_pool_stats()
            print(f"Pool stats: {stats}")
        except Exception as e:
            print(f"Test failed: {e}")
        finally:
            await close()
            print("Redis connections closed")

    asyncio.run(test_redis_manager())