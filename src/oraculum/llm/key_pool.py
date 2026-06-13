"""Thread-safe API-key pool with round-robin selection and per-key cooldown."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


def _key_hash(key: str) -> str:
    """SHA-256 hash of a key for safe persistence."""
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class _Entry:
    key: str
    available_at: float = 0.0


class KeyPool:
    """Thread-safe round-robin pool with per-key cooldown."""

    def __init__(self, keys: list[str], state_path: str | Path | None = None):
        self._entries = [_Entry(k) for k in keys]
        self._lock = threading.Lock()
        self._cursor = 0
        self._state_path = Path(state_path) if state_path else None
        if self._state_path is not None:
            self._load_state()

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def acquire(self) -> str | None:
        """Return the next available key, or the soonest cooling key if all cool."""
        with self._lock:
            if not self._entries:
                return None
            now = time.monotonic()
            n = len(self._entries)
            for i in range(n):
                idx = (self._cursor + i) % n
                if self._entries[idx].available_at <= now:
                    self._cursor = (idx + 1) % n
                    return self._entries[idx].key
            soonest_idx = min(range(n), key=lambda i: self._entries[i].available_at)
            self._cursor = (soonest_idx + 1) % n
            return self._entries[soonest_idx].key

    def cooldown(self, key: str, seconds: float) -> bool:
        """Park a key for at least ``seconds`` without shortening existing cooldown."""
        was_active = False
        with self._lock:
            now = time.monotonic()
            for entry in self._entries:
                if entry.key == key:
                    was_active = entry.available_at <= now
                    entry.available_at = max(entry.available_at, now + max(0.0, seconds))
                    self._save_state_locked()
                    return was_active
        return was_active

    def status(self) -> list[tuple[str, float]]:
        """Return ``(last4, seconds_until_available)`` diagnostics for each key."""
        with self._lock:
            now = time.monotonic()
            return [(e.key[-4:], max(0.0, e.available_at - now)) for e in self._entries]

    def _load_state(self) -> None:
        path = self._state_path
        if path is None or not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read key-pool state from %s: %s", path, exc)
            return
        if not isinstance(data, dict):
            return
        now_wall = time.time()
        now_mono = time.monotonic()
        restored = 0
        for entry in self._entries:
            wall_at = data.get(_key_hash(entry.key))
            if not isinstance(wall_at, int | float):
                continue
            remaining = float(wall_at) - now_wall
            if remaining > 0:
                entry.available_at = now_mono + remaining
                restored += 1
        if restored:
            logger.info("Restored %d cooling Ollama key(s) from %s.", restored, path)

    def _save_state_locked(self) -> None:
        path = self._state_path
        if path is None:
            return
        now_wall = time.time()
        now_mono = time.monotonic()
        out: dict[str, float] = {}
        for entry in self._entries:
            if entry.available_at > now_mono:
                out[_key_hash(entry.key)] = now_wall + (entry.available_at - now_mono)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(out), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Could not persist key-pool state to %s: %s", path, exc)


def extract_retry_after(exc: Exception, default: float = 60.0) -> float:
    """Best-effort parse of Retry-After from common LiteLLM exception shapes."""
    candidates: list[object] = [
        getattr(exc, "response", None),
        getattr(exc, "headers", None),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        headers = getattr(candidate, "headers", candidate)
        getter = getattr(headers, "get", None)
        if not callable(getter):
            continue
        value = getter("retry-after") or getter("Retry-After")
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default
