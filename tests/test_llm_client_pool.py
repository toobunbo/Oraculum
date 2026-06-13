from __future__ import annotations

from types import SimpleNamespace

import pytest

from oraculum.llm import client
from oraculum.llm.key_pool import KeyPool


def _ok_response(content: str = '{"ok": true}') -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


class FakeRateLimitError(Exception):
    pass


class FakeAPIConnectionError(Exception):
    pass


class FakeLiteLLM:
    RateLimitError = FakeRateLimitError
    APIConnectionError = FakeAPIConnectionError

    def __init__(self, fail_key: str | None = None):
        self.fail_key = fail_key
        self.calls: list[str] = []

    def completion(self, **kwargs):
        key = kwargs.get("api_key", "")
        self.calls.append(key)
        if key == self.fail_key:
            raise FakeRateLimitError("rate limited")
        return _ok_response()


def test_build_kwargs_injects_single_cloud_key(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_API_KEYS", "only")
    monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

    kwargs = client._build_completion_kwargs(
        model="qwen3-coder-next:cloud",
        system_prompt="system",
        user_prompt="user",
        temperature=0.0,
        max_tokens=10,
        timeout=30,
        ollama_key_state_path=None,
    )

    assert kwargs["model"] == "ollama_chat/qwen3-coder-next:cloud"
    assert kwargs["api_base"] == "https://ollama.com"
    assert kwargs["api_key"] == "only"
    assert "_oraculum_ollama_pool" not in kwargs


def test_build_kwargs_uses_pool_for_multiple_cloud_keys(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OLLAMA_API_KEYS", "k1,k2,k3")
    monkeypatch.setenv("OLLAMA_API_BASE", "https://ollama.com")
    client._pool_cache.clear()

    kwargs = client._build_completion_kwargs(
        model="ollama_chat/qwen3-coder-next:cloud",
        system_prompt="system",
        user_prompt="user",
        temperature=0.0,
        max_tokens=10,
        timeout=30,
        ollama_key_state_path=tmp_path / ".ollama_key_state.json",
    )

    assert kwargs["api_key"] == "k1"
    assert isinstance(kwargs["_oraculum_ollama_pool"], KeyPool)


def test_local_ollama_does_not_use_pool(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_API_KEYS", "k1,k2")
    monkeypatch.setenv("OLLAMA_API_BASE", "http://localhost:11434")

    kwargs = client._build_completion_kwargs(
        model="ollama/llama3.2",
        system_prompt="system",
        user_prompt="user",
        temperature=0.0,
        max_tokens=10,
        timeout=30,
        ollama_key_state_path=None,
    )

    assert "api_key" not in kwargs
    assert "_oraculum_ollama_pool" not in kwargs


def test_rotation_on_rate_limit() -> None:
    pool = KeyPool(["k1", "k2", "k3"])
    fake_litellm = FakeLiteLLM(fail_key="k1")
    kwargs = {"model": "ollama_chat/model:cloud", "messages": [], "api_key": "k1"}

    response = client._completion_with_rotation(fake_litellm, kwargs, pool)

    assert response.choices[0].message.content == '{"ok": true}'
    assert fake_litellm.calls == ["k1", "k2"]
    assert pool.status()[0][1] > 0


def test_non_quota_connection_error_propagates() -> None:
    class NetworkLiteLLM(FakeLiteLLM):
        def completion(self, **kwargs):
            raise FakeAPIConnectionError("connection refused")

    with pytest.raises(FakeAPIConnectionError):
        client._completion_with_rotation(
            NetworkLiteLLM(),
            {"model": "ollama_chat/model:cloud", "messages": [], "api_key": "k1"},
            KeyPool(["k1", "k2"]),
        )
