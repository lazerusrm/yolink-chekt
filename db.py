"""
Database Module - Redis Connection Management
==========================================

This module provides utility functions for ensuring Redis connectivity.
It now uses the centralized redis_manager module.
"""

import asyncio
import logging
from typing import Optional
from redis.asyncio import Redis
import os
from dotenv import load_dotenv

# Import our Redis connection manager
from redis_manager import get_redis, ensure_connection as ensure_redis_connection

load_dotenv()

logger = logging.getLogger(__name__)


async def ensure_redis_connection(redis_client: Optional[Redis] = None, max_retries: int = 5, delay: int = 2) -> bool:
    """
    Asynchronously ensure that a connection to Redis can be established.
    This function is now a wrapper around redis_manager.ensure_connection for backwards compatibility.

    Args:
        redis_client (Redis, optional): An instance of the asynchronous Redis client, or None to use the shared client.
        max_retries (int, optional): Maximum number of connection attempts. Defaults to 5.
        delay (int, optional): Delay in seconds between attempts. Defaults to 2.

    Returns:
        bool: True if the connection is successful, False otherwise.
    """
    if redis_client is None:
        # Use the shared Redis manager's ensure_connection function
        return await ensure_redis_connection(max_retries=max_retries, backoff_base=delay / 2)

    # For cases where a specific client instance was provided
    for attempt in range(max_retries):
        try:
            await redis_client.ping()
            logger.info("Successfully connected to Redis")
            return True
        except Exception as e:
            logger.warning(f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts: {e}")
                return False
    return False


# Example usage:
if __name__ == "__main__":
    async def main():
        # Set up logging
        logging.basicConfig(level=logging.DEBUG)
        logger.info("Testing Redis connection utilities")

        # Test with the shared Redis client
        success = await ensure_redis_connection()
        print(f"Redis connection successful (using shared client): {success}")

        # Create a custom Redis client for testing
        custom_redis_client = Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=True
        )

        # Test with a custom client
        success = await ensure_redis_connection(custom_redis_client)
        print(f"Redis connection successful (using custom client): {success}")

        # Clean up
        await custom_redis_client.close()
        await custom_redis_client.connection_pool.disconnect()

        # Clean up shared Redis connection
        from redis_manager import close
        await close()


    asyncio.run(main())