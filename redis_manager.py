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


async def get_redis() -> 'Redis':
    """
    Retrieve or establish an asynchronous Redis client instance using a shared connection pool.

    This function manages a single Redis connection pool globally, creating it if necessary,
    and returns a Redis client instance. It ensures the client is alive by testing connectivity
    and reinitializes the pool if the connection is lost or unavailable.

    Returns:
        Redis: An asynchronous Redis client instance configured with the shared connection pool.

    Raises:
        ConnectionError: If the Redis connection cannot be established or verified after retries.
    """
    global _redis_client, _pool, _initializing
    from redis.asyncio import Redis, ConnectionPool
    import asyncio

    # Configuration for Redis connection
    redis_config = {
        "host": "redis",
        "port": 6379,
        "db": 0,
        "decode_responses": True,
        "max_connections": 200
    }

    async with _lock:  # Ensure thread-safe initialization
        # Check if the current client is usable
        if _redis_client is None or not await _is_redis_connected(_redis_client):
            logger.debug(f"Initializing or reinitializing Redis connection pool: host={redis_config['host']}, "
                         f"port={redis_config['port']}, max_connections={redis_config['max_connections']}")

            # If the pool doesn't exist or needs recreation, initialize it
            if _pool is None:
                logger.debug("Creating new Redis connection pool")
                _pool = ConnectionPool(
                    host=redis_config["host"],
                    port=redis_config["port"],
                    db=redis_config["db"],
                    decode_responses=redis_config["decode_responses"],
                    max_connections=redis_config["max_connections"]
                )

            # Mark initialization in progress to prevent concurrent attempts
            _initializing = True
            try:
                # Create a new Redis client with the pool
                new_client = Redis(connection_pool=_pool)
                logger.debug("Testing Redis connectivity with ping")

                # Attempt to ping Redis with retries
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        await new_client.ping()
                        logger.info(f"Successfully connected to Redis at {redis_config['host']}:{redis_config['port']}, "
                                    f"db={redis_config['db']}")
                        _redis_client = new_client
                        break
                    except Exception as ping_error:
                        logger.warning(f"Redis ping failed on attempt {attempt + 1}/{max_retries}: {ping_error}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)  # Wait before retrying
                        else:
                            logger.error(f"Failed to connect to Redis after {max_retries} attempts: {ping_error}")
                            _redis_client = None
                            raise ConnectionError(f"Unable to establish Redis connection: {ping_error}")

                # Log connection pool statistics after successful connection
                pool_stats = await get_pool_stats()
                logger.debug(f"Connection pool stats after initialization: {pool_stats}")

            except Exception as error:
                logger.error(f"Redis initialization failed: {error}", exc_info=True)
                _redis_client = None
                raise ConnectionError(f"Redis connection setup failed: {error}")
            finally:
                _initializing = False
        else:
            # Reuse existing client if it's alive
            logger.debug("Using existing Redis client")
            pool_stats = await get_pool_stats()
            logger.debug(f"Connection pool stats before reuse: {pool_stats}")

        # Handle case where another task is initializing
        if _initializing:
            logger.debug("Another task is initializing Redis, waiting briefly")
            await asyncio.sleep(0.2)  # Brief delay to avoid race condition

    return _redis_client

async def _is_redis_connected(client: 'Redis') -> bool:
    """
    Check if the provided Redis client is connected and responsive.

    Args:
        client (Redis): The Redis client instance to test.

    Returns:
        bool: True if the client is connected and responsive, False otherwise.
    """
    if client is None:
        return False
    try:
        await client.ping()
        return True
    except Exception:
        return False


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