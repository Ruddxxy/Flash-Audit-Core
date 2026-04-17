"""
Distributed rate limiter with Redis backend and in-memory fallback.

Uses a sliding window algorithm:
- Redis: sorted sets (ZADD/ZREMRANGEBYSCORE/ZCARD) for distributed tracking
- Memory: timestamp lists for single-process development
"""

import logging
import os
import time
from typing import Optional

logger = logging.getLogger("flashaudit.rate_limiter")

REDIS_URL = os.getenv("REDIS_URL", "")

# Global Redis connection (initialized via connect())
_redis_client = None


async def connect() -> None:
    """Connect to Redis if REDIS_URL is set. Called during app startup."""
    global _redis_client
    if REDIS_URL:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
            await _redis_client.ping()
            logger.info("Redis rate limiter connected")
        except Exception:
            logger.warning(
                "Redis connection failed — falling back to in-memory rate limiting. "
                "This is fine for single-process dev but not for production."
            )
            _redis_client = None
    else:
        logger.info("No REDIS_URL set — using in-memory rate limiting")


async def close() -> None:
    """Close Redis connection. Called during app shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


class RateLimiter:
    """Sliding window rate limiter with Redis or in-memory backend."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._memory: dict[str, list[float]] = {}

    async def is_allowed(self, key: str) -> bool:
        """Check if request is allowed and record it."""
        if _redis_client is not None:
            return await self._is_allowed_redis(key)
        return self._is_allowed_memory(key)

    async def get_retry_after(self, key: str) -> int:
        """Seconds until the next request would be allowed."""
        if _redis_client is not None:
            return await self._get_retry_after_redis(key)
        return self._get_retry_after_memory(key)

    # --- Redis backend ---

    async def _is_allowed_redis(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        redis_key = f"rl:{key}"

        pipe = _redis_client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {str(now): now})
        pipe.expire(redis_key, self.window_seconds)
        results = await pipe.execute()

        count = results[1]
        if count >= self.max_requests:
            # Remove the request we just added — it shouldn't count
            await _redis_client.zrem(redis_key, str(now))
            return False
        return True

    async def _get_retry_after_redis(self, key: str) -> int:
        redis_key = f"rl:{key}"
        oldest = await _redis_client.zrange(redis_key, 0, 0, withscores=True)
        if not oldest:
            return 0
        oldest_time = oldest[0][1]
        retry_after = int(self.window_seconds - (time.time() - oldest_time))
        return max(0, retry_after)

    # --- In-memory backend ---

    def _is_allowed_memory(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        timestamps = self._memory.get(key, [])
        valid = [ts for ts in timestamps if ts > window_start]

        if len(valid) >= self.max_requests:
            self._memory[key] = valid
            return False

        valid.append(now)
        self._memory[key] = valid
        return True

    def _get_retry_after_memory(self, key: str) -> int:
        timestamps = self._memory.get(key, [])
        if not timestamps:
            return 0
        oldest = min(timestamps)
        retry_after = int(self.window_seconds - (time.time() - oldest))
        return max(0, retry_after)

    def reset(self) -> None:
        """Clear in-memory state (for testing)."""
        self._memory.clear()


# Singleton instances configured from environment
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

cli_rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)

LOGIN_RATE_LIMIT_MAX = int(os.getenv("LOGIN_RATE_LIMIT_MAX", "5"))
LOGIN_RATE_LIMIT_WINDOW = 60

login_rate_limiter = RateLimiter(LOGIN_RATE_LIMIT_MAX, LOGIN_RATE_LIMIT_WINDOW)
