from __future__ import annotations

import json
import time
from contextlib import contextmanager
from threading import Lock
from typing import Any, Iterator, Optional

import redis

from .config import settings


class Cache:
    def __init__(self) -> None:
        self._client: Optional[redis.Redis] = None
        self._memory: dict[str, tuple[float, str]] = {}
        self._guard = Lock()
        try:
            client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=1)
            client.ping()
            self._client = client
        except (redis.RedisError, OSError):
            self._client = None

    @property
    def backend(self) -> str:
        return "redis" if self._client else "memory-fallback"

    def get_json(self, key: str) -> Optional[Any]:
        if self._client:
            try:
                value = self._client.get(key)
                return json.loads(value) if value else None
            except (redis.RedisError, json.JSONDecodeError):
                pass
        item = self._memory.get(key)
        if not item or item[0] < time.time():
            self._memory.pop(key, None)
            return None
        return json.loads(item[1])

    def set_json(self, key: str, value: Any, ttl: int = 60) -> None:
        payload = json.dumps(value, ensure_ascii=False, default=str)
        if self._client:
            try:
                self._client.setex(key, ttl, payload)
                return
            except redis.RedisError:
                pass
        self._memory[key] = (time.time() + ttl, payload)

    def delete(self, key: str) -> None:
        if self._client:
            try:
                self._client.delete(key)
            except redis.RedisError:
                pass
        with self._guard:
            self._memory.pop(key, None)

    def delete_pattern(self, pattern: str) -> None:
        if self._client:
            try:
                keys = list(self._client.scan_iter(match=pattern, count=100))
                if keys:
                    self._client.delete(*keys)
            except redis.RedisError:
                pass
        prefix = pattern.rstrip("*")
        for key in list(self._memory):
            if key.startswith(prefix):
                self._memory.pop(key, None)

    def hit_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        if self._client:
            try:
                with self._client.pipeline() as pipe:
                    pipe.incr(key)
                    pipe.expire(key, window_seconds, nx=True)
                    count, _ = pipe.execute()
                return int(count) > limit
            except redis.RedisError:
                pass
        with self._guard:
            expires, raw = self._memory.get(key, (time.time() + window_seconds, "0"))
            if expires < time.time():
                expires, raw = time.time() + window_seconds, "0"
            count = int(raw) + 1
            self._memory[key] = (expires, str(count))
            return count > limit

    @contextmanager
    def lock(self, name: str, timeout: int = 60) -> Iterator[bool]:
        if self._client:
            lock = self._client.lock(name, timeout=timeout, blocking_timeout=1)
            acquired = False
            try:
                acquired = bool(lock.acquire(blocking=True))
            except redis.RedisError:
                acquired = True
            try:
                yield acquired
            finally:
                if acquired and self._client:
                    try:
                        lock.release()
                    except redis.RedisError:
                        pass
        else:
            with self._guard:
                yield True


cache = Cache()
