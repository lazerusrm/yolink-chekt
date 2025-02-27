import redis
import logging

logger = logging.getLogger(__name__)

# Use Docker Compose service name 'redis' instead of localhost
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

def test_connection():
    try:
        redis_client.ping()
        logger.info("Redis connection successful")
    except redis.ConnectionError as e:
        logger.error(f"Redis connection failed: {e}")
        raise