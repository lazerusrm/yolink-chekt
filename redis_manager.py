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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global connection pool and client
_pool: Optional[ConnectionPool] = None
_redis_client: Optional[Redis] = None

# Configuration with environment variable fallbacks
_config: Dict[str, Any] = {
    "host": os.getenv("REDIS_HOST", "redis"),
    "port": int(os.getenv("REDIS_PORT", 6379)),
    "db": int(os.getenv("REDIS_DB", 0)),
    "decode_responses": True,  # Decode responses as strings
    "max_connections": int(os.getenv("REDIS_MAX_CONNECTIONS", 10))
}

async def get_redis() -> Redis:
    """
    Get or create a Redis client using the shared connection pool.

    Returns:
        Redis: An async Redis client instance

    Raises:
        ConnectionError: If connection to Redis fails
    """
    global _redis_client, _pool

    if _redis_client is None:
        if _pool is None or _pool.disconnected:
            logger.debug(f"Creating new Redis connection pool: host={_config['host']}, port={_config['port']}")
            _pool = ConnectionPool(
                host=_config["host"],
                port=_config["port"],
                db=_config["db"],
                decode_responses=_config["decode_responses"],
                max_connections=_config["max_connections"]
            )

        _redis_client = Redis(connection_pool=_pool)
        try:
            await _redis_client.ping()
            logger.info(f"Connected to Redis at {_config['host']}:{_config['port']}, db={_config['db']}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            _redis_client = None
            raise ConnectionError(f"Redis connection failed: {e}")

    return _redis_client

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
            wait_time = min(30, backoff_base ** attempt)  # Cap at 30s
            logger.warning(
                f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}. "
                f"Retrying in {wait_time:.1f}s"
            )
            if attempt < max_retries - 1:
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts")
                _redis_client = None  # Reset client on final failure
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

    try:
        # Update configuration
        _config.update(new_config)
        logger.info(f"Updated Redis config: {json.dumps(_config, indent=2)}")

        # Close existing connections
        if _redis_client is not None:
            await _redis_client.close()
            _redis_client = None
        if _pool is not None:
            await _pool.disconnect()
            _pool = None

        # Re-establish connection with new config
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

if __name__ == "__main__":
    async def test_redis_manager():
        """Test the Redis manager standalone."""
        logging.basicConfig(level=logging.DEBUG)
        try:
            # Get Redis client and test basic operations
            redis = await get_redis()
            await redis.set("test_key", "test_value")
            value = await redis.get("test_key")
            print(f"Set and retrieved test value: {value}")

            # Test ensure_connection
            connected = await ensure_connection(max_retries=3, backoff_base=1.0)
            print(f"Ensure connection result: {connected}")

            # Test config update
            new_config = {"port": 6379, "max_connections": 20}
            updated = await update_config(new_config)
            print(f"Config update result: {updated}")

            # Verify connection still works
            await redis.set("post_update_key", "updated")
            print(f"Post-update value: {await redis.get('post_update_key')}")
        except Exception as e:
            print(f"Test failed: {e}")
        finally:
            await close()
            print("Redis connections closed")

    asyncio.run(test_redis_manager())