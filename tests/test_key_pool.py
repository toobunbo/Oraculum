from __future__ import annotations

import json
import threading
import time
from collections import Counter

import pytest

from oraculum.llm.key_pool import KeyPool, extract_retry_after


def test_empty_pool_returns_none() -> None:
    pool = KeyPool([])

    assert pool.acquire() is None
    assert len(pool) == 0
    assert not pool


def test_round_robin_order() -> None:
    pool = KeyPool(["a", "b", "c"])

    assert [pool.acquire() for _ in range(6)] == ["a", "b", "c", "a", "b", "c"]


def test_cooldown_skips_parked_key() -> None:
    pool = KeyPool(["a", "b"])

    assert pool.cooldown("a", 60) is True
    assert [pool.acquire() for _ in range(3)] == ["b", "b", "b"]
    assert pool.cooldown("a", 60) is False


def test_all_keys_cooling_returns_soonest_available() -> None:
    pool = KeyPool(["a", "b"])

    pool.cooldown("a", 120)
    pool.cooldown("b", 5)

    assert pool.acquire() == "b"


def test_cooldown_expires() -> None:
    pool = KeyPool(["a", "b"])

    pool.cooldown("a", 0.03)
    assert pool.acquire() == "b"
    time.sleep(0.05)

    assert {pool.acquire(), pool.acquire()} == {"a", "b"}


def test_persistence_uses_hashes_and_restores(tmp_path) -> None:
    state = tmp_path / "key_state.json"
    pool = KeyPool(["secret-a", "secret-b"], state_path=state)

    pool.cooldown("secret-a", 3600)

    content = state.read_text(encoding="utf-8")
    assert "secret-a" not in content

    restored = KeyPool(["secret-a", "secret-b"], state_path=state)
    assert {restored.acquire() for _ in range(3)} == {"secret-b"}


def test_expired_persistence_is_ignored(tmp_path) -> None:
    state = tmp_path / "key_state.json"
    state.write_text(
        json.dumps(
            {
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb": (
                    time.time() - 100
                )
            }
        ),
        encoding="utf-8",
    )

    pool = KeyPool(["a", "b"], state_path=state)

    assert {pool.acquire() for _ in range(4)} == {"a", "b"}


def test_concurrent_acquire_distributes_evenly() -> None:
    pool = KeyPool(["k1", "k2", "k3", "k4"])
    counter: Counter[str] = Counter()
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(250):
            key = pool.acquire()
            with lock:
                counter[str(key)] += 1

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(counter.values()) == 2000
    assert all(475 <= counter[key] <= 525 for key in ["k1", "k2", "k3", "k4"])


def test_extract_retry_after_default() -> None:
    assert extract_retry_after(Exception("no headers"), default=30.0) == 30.0


def test_extract_retry_after_from_headers_attr() -> None:
    exc = Exception("rate-limited")
    exc.headers = {"retry-after": "7"}  # type: ignore[attr-defined]

    assert extract_retry_after(exc) == 7.0


def test_extract_retry_after_from_response_headers() -> None:
    class FakeResponse:
        headers = {"Retry-After": "12.5"}

    exc = Exception("rate-limited")
    exc.response = FakeResponse()  # type: ignore[attr-defined]

    assert extract_retry_after(exc) == pytest.approx(12.5)
