"""
Redis Connection Manager - Shared Redis Client Pool
===================================================

This module provides a centralized Redis connection manager to avoid
creating multiple Redis client instances across the application.
It maintains a single connection pool and handles reconnection logic.
"""

import os
import logging
import asyncio
from typing import Optional, Dict, Any
from redis.asyncio import Redis, ConnectionPool
from dotenv import load_dotenv

load_dotenv()

# Logging setup
logger = logging.getLogger(__name__)

# Global connection pool
_pool: Optional[ConnectionPool] = None
# Global Redis client
_redis_client: Optional[Redis] = None
# Configuration
_config: Dict[str, Any] = {
    "host": os.getenv("REDIS_HOST", "redis"),
    "port": int(os.getenv("REDIS_PORT", 6379)),
    "db": int(os.getenv("REDIS_DB", 0)),
    "decode_responses": True,
    "max_connections": 10
}


async def get_redis() -> Redis:
    """
    Get or create a Redis client using the shared connection pool.

    Returns:
        Redis: An async Redis client instance
    """
    global _redis_client, _pool

    if _redis_client is None:
        if _pool is None:
            logger.debug("Creating new Redis connection pool")
            _pool = ConnectionPool(
                host=_config["host"],
                port=_config["port"],
                db=_config["db"],
                decode_responses=_config["decode_responses"],
                max_connections=_config["max_connections"]
            )

        logger.debug("Creating new Redis client with connection pool")
        _redis_client = Redis(connection_pool=_pool)

        # Test the connection
        try:
            await _redis_client.ping()
            logger.info(f"Connected to Redis at {_config['host']}:{_config['port']}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            _redis_client = None
            raise

    return _redis_client


async def ensure_connection(max_retries: int = 5, backoff_base: float = 1.5) -> bool:
    """
    Ensure a Redis connection is established with exponential backoff.

    Args:
        max_retries (int): Maximum number of connection attempts
        backoff_base (float): Base for exponential backoff calculation

    Returns:
        bool: True if connected successfully, False otherwise
    """
    for attempt in range(max_retries):
        try:
            client = await get_redis()
            await client.ping()
            if attempt > 0:
                logger.info(f"Successfully reconnected to Redis after {attempt + 1} attempts")
            return True
        except Exception as e:
            wait_time = min(30, backoff_base ** attempt)
            logger.warning(
                f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {wait_time:.1f}s")
            if attempt < max_retries - 1:
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts")
                return False
    return False


async def update_config(new_config: Dict[str, Any]) -> None:
    """
    Update Redis configuration and reset the connection.

    Args:
        new_config (Dict[str, Any]): New configuration values
    """
    global _config, _redis_client, _pool

    # Update config with new values
    _config.update(new_config)

    # Close existing connections
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None

    if _pool is not None:
        await _pool.disconnect()
        _pool = None

    logger.info("Redis configuration updated, connections reset")


async def close() -> None:
    """
    Close Redis connections and clean up resources.
    """
    global _redis_client, _pool

    if _redis_client is not None:
        try:
            await _redis_client.close()
            logger.info("Redis client closed")
        except Exception as e:
            logger.error(f"Error closing Redis client: {e}")
        finally:
            _redis_client = None

    if _pool is not None:
        try:
            await _pool.disconnect()
            logger.info("Redis connection pool disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting Redis pool: {e}")
        finally:
            _pool = None


# Example usage
if __name__ == "__main__":
    async def main():
        logging.basicConfig(level=logging.DEBUG)
        try:
            redis = await get_redis()
            await redis.set("test_key", "test_value")
            value = await redis.get("test_key")
            print(f"Retrieved test value: {value}")

            # Test connection ensure
            connected = await ensure_connection()
            print(f"Connection test result: {connected}")
        finally:
            await close()


    asyncio.run(main())