import aioredis

from .config import REDIS_HOST, REDIS_PORT


redis = aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}")
