import redis
import os
import time
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),  # Use Docker service name 'redis'
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=0,
    decode_responses=True
)

def ensure_redis_connection(max_retries=5, delay=2):
    for attempt in range(max_retries):
        try:
            redis_client.ping()
            logger.info("Successfully connected to Redis")
            return True
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts: {e}")
                return False
    return False