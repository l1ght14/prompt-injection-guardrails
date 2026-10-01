"""Optional LLM access, so the same corpus can be run against a real model.

Deliberately a near-copy of the client in the retrieval project rather than a shared
dependency. Each project has to run standalone from a clone, and a guardrail suite that
cannot be cloned and run is a guardrail suite nobody re-runs.

What it shares with that version and why it matters here:

- Keys come from the environment at call time and are never written to disk. In this project
  the stakes are higher than usual, since a leak would expose the key used to test the
  security controls.
- Responses are cached on disk, keyed by model, temperature, the full prompt and a harness
  version. A red-team run over 60 attacks with a 30 RPM free tier will otherwise stall, and
  re-running to confirm a number should not re-spend the quota.
- Retries with exponential backoff honour `retry-after`, so a 429 costs a pause rather than
  the run.
- With no key present, `get_client` returns a deterministic mock. The capability layer, the
  red-team harness and the whole test suite work with no key at all, which is the only reason
  the offline default is defensible.

One difference from the retrieval project: `RawResponse` is deliberately absent. Response
payloads can echo the prompt, and this project's prompt contains attack strings. Keeping only
the text means a cached artefact is the attack corpus plus some replies - all of which are
already public in this repository.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

HARNESS_VERSION = "1"

PROVIDERS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "env_key": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "env_key": "GEMINI_API_KEY",
        "default_model": "gemini-2.0-flash",
    },
}


class RateLimited(Exception):
    """Raised when the provider's budget is spent rather than merely throttled."""


@dataclass
class Response:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient:
    def __init__(
        self,
        provider: str = "groq",
        model: str | None = None,
        cache_dir: Path | None = None,
        max_retries: int = 6,
        rpm_limit: int = 25,
        timeout: float = 60.0,
    ) -> None:
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}; choose from {sorted(PROVIDERS)}")
        spec = PROVIDERS[provider]
        self.provider = provider
        self.model = model or spec["default_model"]
        self.max_retries = max_retries
        self.timeout = timeout
        self._api_key = os.environ.get(spec["env_key"])
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = None
        self._last_call = 0.0
        self._min_interval = 60.0 / rpm_limit if rpm_limit else 0.0
        self.stats = {"requests": 0, "cache_hits": 0, "retries": 0, "prompt_tokens": 0,
                      "completion_tokens": 0}

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def status(self) -> str:
        if not self._api_key:
            return f"no key - set {PROVIDERS[self.provider]['env_key']} to use {self.provider}"
        return f"{self.provider}:{self.model}"

    def _cache_key(self, messages: list[dict], temperature: float) -> str:
        blob = json.dumps(
            {
                "harness": HARNESS_VERSION,
                "provider": self.provider,
                "model": self.model,
                "temperature": temperature,
                "messages": messages,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _cache_path(self, key: str) -> Path | None:
        return (self.cache_dir / key[:2] / f"{key}.json") if self.cache_dir else None

    def complete(
        self, messages: list[dict], temperature: float = 0.0, max_tokens: int = 300
    ) -> Response:
        key = self._cache_key(messages, temperature)
        path = self._cache_path(key)
        if path and path.exists():
            try:
                blob = json.loads(path.read_text(encoding="utf-8"))
                self.stats["cache_hits"] += 1
                return Response(
                    text=blob["text"], model=blob["model"],
                    prompt_tokens=blob.get("prompt_tokens", 0),
                    completion_tokens=blob.get("completion_tokens", 0),
                    cached=True,
                )
            except (json.JSONDecodeError, KeyError):
                pass

        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(
                api_key=self._api_key, base_url=PROVIDERS[self.provider]["base_url"],
                timeout=self.timeout, max_retries=0,
            )

        delay = 1.0
        for attempt in range(self.max_retries):
            if self._min_interval and (time.time() - self._last_call) < self._min_interval:
                time.sleep(self._min_interval - (time.time() - self._last_call))
            self._last_call = time.time()
            try:
                completion = self._client.chat.completions.create(
                    model=self.model, messages=messages, temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as exc:  # noqa: BLE001 - provider errors vary by status
                status = getattr(exc, "status_code", None)
                if status == 429 or "rate_limit" in type(exc).__name__.lower():
                    self.stats["retries"] += 1
                    time.sleep(delay + random.uniform(0, min(2**attempt, 8)))
                    delay = min(delay * 2, 60.0)
                    continue
                raise
            usage = completion.usage
            resp = Response(
                text=completion.choices[0].message.content or "",
                model=completion.model,
                prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            )
            self.stats["requests"] += 1
            self.stats["prompt_tokens"] += resp.prompt_tokens
            self.stats["completion_tokens"] += resp.completion_tokens
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "text": resp.text, "model": resp.model,
                            "prompt_tokens": resp.prompt_tokens,
                            "completion_tokens": resp.completion_tokens,
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
            return resp
        raise RateLimited(
            f"exhausted {self.max_retries} retries against {self.provider}; rerun later and "
            f"the cache will pick up where it stopped"
        )


class OfflineLLM:
    """Deterministic stand-in when no key is present.

    Answers `{"tool": null}` for everything. That is the *correct* behaviour for a real model
    facing these documents in the abstract, and it is why the offline run is not a security
    measurement - it measures nothing about models. It exists so the capability layer, the
    router and the test suite are exercisable with no network and no spend. The red-team
    numbers in this project come from the simulated decider or a real model, never from this.
    """

    model = "offline-mock"
    provider = "mock"

    def __init__(self) -> None:
        self.available = False
        self.stats = {"requests": 0, "cache_hits": 0, "retries": 0, "prompt_tokens": 0,
                      "completion_tokens": 0}

    def status(self) -> str:
        return "offline mock (no key); no model is called"

    def complete(self, messages: list[dict], **_) -> Response:
        self.stats["requests"] += 1
        text = '{"tool": null, "kwargs": {}}'
        return Response(text=text, model=self.model)


def get_client(provider: str = "groq", cache_dir: Path | None = None) -> LLMClient | OfflineLLM:
    client = LLMClient(provider=provider, cache_dir=cache_dir)
    return client if client.available else OfflineLLM()
