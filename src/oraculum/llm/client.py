"""Shared LiteLLM completion helper with Ollama Cloud multi-key rotation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, cast

from oraculum.llm.key_pool import KeyPool, extract_retry_after

logger = logging.getLogger(__name__)

_OLLAMA_QUOTA_MARKERS = (
    "session usage limit",
    "upgrade for higher limits",
    "daily usage limit",
    "monthly usage limit",
)
_OLLAMA_QUOTA_COOLDOWN_S = 6 * 3600

_pool_cache: dict[tuple[tuple[str, ...], str], KeyPool] = {}


def load_ollama_api_keys() -> list[str]:
    """Parse comma-separated Ollama Cloud bearer tokens from OLLAMA_API_KEYS."""
    raw = os.environ.get("OLLAMA_API_KEYS", "")
    return [key.strip() for key in raw.split(",") if key.strip()]


def check_ollama_keys(model: str, api_base: str | None = None) -> tuple[bool, str]:
    """Smoke-test every configured Ollama Cloud key."""
    import litellm

    bare_model = model.removeprefix("ollama_chat/").removeprefix("ollama/")
    tag_is_cloud = bare_model.endswith(":cloud") or bare_model.endswith("-cloud")
    resolved_base = (api_base or os.environ.get("OLLAMA_API_BASE", "")).strip()
    is_cloud = "ollama.com" in resolved_base or tag_is_cloud
    if not is_cloud:
        return True, "Ollama local mode; no key check needed"

    keys = load_ollama_api_keys()
    if not keys:
        return False, "Ollama Cloud detected but OLLAMA_API_KEYS is not set"

    if "ollama.com" not in resolved_base:
        resolved_base = "https://ollama.com"
    full_model = f"ollama_chat/{bare_model}"
    base_kwargs = {
        "model": full_model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "max_tokens": 10,
        "api_base": resolved_base.rstrip("/"),
    }

    failures = 0
    summaries: list[str] = []
    for key in keys:
        tail = key[-4:]
        try:
            response = litellm.completion(**{**base_kwargs, "api_key": key})
            text = (response.choices[0].message.content or "").strip()
            summaries.append(f"...{tail}=OK ({text[:20]})")
        except Exception as exc:
            failures += 1
            summaries.append(f"...{tail}=FAIL ({exc})")

    summary = (
        f"Ollama ({full_model}) @ {resolved_base}: {len(keys)} key(s); "
        + "; ".join(summaries)
    )
    return failures == 0, summary


import time


def call_llm(
    *,
    system_prompt: str,
    user_prompt: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    ollama_key_state_path: str | Path | None = None,
) -> str:
    """Call LiteLLM, rotating Ollama Cloud keys on rate-limit/quota failures."""
    _silence_litellm_optional_provider_warnings()
    import litellm

    logging.debug("\n========== LLM REQUEST ==========")
    logging.debug("[SYSTEM PROMPT]\n%s\n", system_prompt)
    logging.debug("[USER PROMPT]\n%s\n", user_prompt)

    kwargs = _build_completion_kwargs(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        ollama_key_state_path=ollama_key_state_path,
    )
    pool = kwargs.pop("_oraculum_ollama_pool", None)

    max_attempts = 4
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = _completion_with_rotation(litellm, kwargs, pool)
            content = cast(str, response.choices[0].message.content)
            logging.debug("========== LLM RESPONSE ==========\n%s\n==================================", content)
            return content
        except (litellm.RateLimitError, litellm.Timeout) as e:
            last_error = e
            if attempt < max_attempts:
                delay = min(30, 2 ** (attempt + 1))
                etype = "Rate limited" if isinstance(e, litellm.RateLimitError) else "Timed out"
                logger.warning(
                    "%s on %s (attempt %d/%d); retrying in %ds...",
                    etype, model, attempt, max_attempts, delay,
                )
                time.sleep(delay)
            else:
                raise
        except Exception:
            raise

    raise last_error  # type: ignore[misc]


def _build_completion_kwargs(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    ollama_key_state_path: str | Path | None,
) -> dict[str, Any]:
    normalized_model, is_ollama_cloud = _normalize_ollama_model_and_base(model)
    kwargs: dict[str, Any] = {
        "model": normalized_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": timeout,
    }

    if not is_ollama_cloud:
        return kwargs

    kwargs["api_base"] = os.environ["OLLAMA_API_BASE"].rstrip("/")
    keys = load_ollama_api_keys()
    if len(keys) == 1:
        kwargs["api_key"] = keys[0]
    elif len(keys) >= 2:
        pool = _get_pool(keys, ollama_key_state_path)
        pooled = pool.acquire()
        if pooled:
            kwargs["api_key"] = pooled
        kwargs["_oraculum_ollama_pool"] = pool
    return kwargs


def _normalize_ollama_model_and_base(model: str) -> tuple[str, bool]:
    bare_model = model.removeprefix("ollama_chat/").removeprefix("ollama/")
    api_base = os.environ.get("OLLAMA_API_BASE", "").strip()
    tag_is_cloud = bare_model.endswith(":cloud") or bare_model.endswith("-cloud")
    is_ollama_model = model.startswith(("ollama/", "ollama_chat/")) or bool(api_base) or tag_is_cloud
    is_cloud = is_ollama_model and ("ollama.com" in api_base or tag_is_cloud)

    if not is_ollama_model:
        return model, False
    if is_cloud:
        if "ollama.com" not in api_base:
            api_base = "https://ollama.com"
        os.environ["OLLAMA_API_BASE"] = api_base
        return f"ollama_chat/{bare_model}", True

    os.environ["OLLAMA_API_BASE"] = api_base or "http://localhost:11434"
    if model.startswith(("ollama/", "ollama_chat/")):
        return model, False
    return f"ollama/{bare_model}", False


def _get_pool(keys: list[str], state_path: str | Path | None) -> KeyPool:
    cache_key = (tuple(keys), str(Path(state_path)) if state_path else "")
    pool = _pool_cache.get(cache_key)
    if pool is not None:
        return pool
    pool = KeyPool(keys, state_path=state_path)
    _pool_cache[cache_key] = pool
    status = pool.status()
    cooling = [(tail, secs) for tail, secs in status if secs > 0]
    logger.info(
        "Ollama Cloud key pool: %d key(s) [%s]%s",
        len(status),
        ", ".join("..." + tail for tail, _ in status),
        (
            "; "
            + str(len(cooling))
            + " cooling from prior runs: "
            + ", ".join(f"...{tail} ({int(secs)}s)" for tail, secs in cooling)
            if cooling
            else ""
        ),
    )
    return pool


def _completion_with_rotation(litellm: Any, kwargs: dict[str, Any], pool: KeyPool | None) -> Any:
    if pool is None:
        return litellm.completion(**kwargs)

    max_attempts = max(len(pool), 1)
    last_err: Exception | None = None
    for _ in range(max_attempts):
        try:
            return litellm.completion(**kwargs)
        except litellm.RateLimitError as exc:
            key = kwargs.get("api_key")
            if key:
                fresh = pool.cooldown(str(key), extract_retry_after(exc))
                if fresh:
                    logger.warning(
                        "Ollama Cloud rate limited key ending ...%s; rotating.",
                        str(key)[-4:],
                    )
            last_err = exc
        except litellm.APIConnectionError as exc:
            if not _is_ollama_quota_error(exc):
                raise
            key = kwargs.get("api_key")
            if key:
                fresh = pool.cooldown(str(key), _OLLAMA_QUOTA_COOLDOWN_S)
                if fresh:
                    logger.warning(
                        "Ollama Cloud quota exhausted on key ending ...%s; parking for %ds.",
                        str(key)[-4:],
                        _OLLAMA_QUOTA_COOLDOWN_S,
                    )
            last_err = exc
        next_key = pool.acquire()
        if next_key:
            kwargs["api_key"] = next_key

    if last_err is not None:
        raise last_err
    return litellm.completion(**kwargs)


def _is_ollama_quota_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(marker in message for marker in _OLLAMA_QUOTA_MARKERS)


def _silence_litellm_optional_provider_warnings() -> None:
    """Suppress noisy LiteLLM warnings for optional providers we do not use."""
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    for logger_name in ("LiteLLM", "litellm"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)
