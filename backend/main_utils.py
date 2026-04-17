"""
Shared utilities extracted from main.py.
Keeps the rate limiter accessible to both main.py and routers/cli.py.
"""

import os
import time


RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))


class RateLimiter:
    """
    Simple in-memory rate limiter.
    Production: Replace with Redis-based implementation for distributed systems.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        timestamps = self._requests.get(key, [])
        valid_timestamps = [ts for ts in timestamps if ts > window_start]

        if len(valid_timestamps) >= self.max_requests:
            return False

        valid_timestamps.append(now)
        self._requests[key] = valid_timestamps
        return True

    def get_retry_after(self, key: str) -> int:
        timestamps = self._requests.get(key, [])
        if not timestamps:
            return 0
        oldest = min(timestamps)
        retry_after = int(self.window_seconds - (time.time() - oldest))
        return max(0, retry_after)


rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
