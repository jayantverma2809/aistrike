"""
LLM client abstraction.

Supports OpenAI and Anthropic; extensible via the get_client() factory.
"""

import json
import logging
from typing import Any, Optional, Protocol, runtime_checkable, Type

from pydantic import BaseModel

from src.config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL, LLM_PROVIDER, OPENAI_API_KEY, get_llm_model

logger = logging.getLogger(__name__)


# ── Protocol (interface) ──────────────────────────────────────────────────────

@runtime_checkable
class LLMClient(Protocol):
    """Minimal interface every LLM backend must implement."""

    def generate_json(
        self,
        system: str,
        user: str,
        response_schema: Type[BaseModel],
    ) -> BaseModel:
        """Send a chat completion and parse the JSON response into response_schema."""
        ...

    @property
    def last_usage(self) -> dict[str, int]:
        """Token usage from the most recent call (prompt/completion/total)."""
        ...

    def clone(self) -> "LLMClient":
        """Return a fresh instance with the same configuration (for thread-safety)."""
        ...


# ── OpenAI implementation ─────────────────────────────────────────────────────

class OpenAIClient:
    """OpenAI chat completion client. Temperature=0, JSON-mode, seed=42."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("openai package is required: pip install openai>=1.40") from exc

        self._model = model or get_llm_model()
        self._client = OpenAI(api_key=api_key or OPENAI_API_KEY or None)
        self._usage: dict[str, int] = {}

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self._usage)

    def clone(self) -> "OpenAIClient":
        return OpenAIClient(model=self._model)

    def generate_json(
        self,
        system: str,
        user: str,
        response_schema: Type[BaseModel],
    ) -> BaseModel:
        logger.debug("Calling OpenAI model=%s …", self._model)

        response = self._client.chat.completions.create(
            model=self._model,
            temperature=0,
            seed=42,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )

        if response.usage:
            self._usage = {
                "prompt_tokens":     response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens":      response.usage.total_tokens,
            }

        raw = response.choices[0].message.content or ""
        try:
            data = json.loads(raw)
            return response_schema.model_validate(data)
        except Exception as exc:
            raise ValueError(
                f"Failed to parse OpenAI response into {response_schema.__name__}.\n"
                f"Raw response:\n{raw}\nError: {exc}"
            ) from exc


# ── Anthropic implementation ──────────────────────────────────────────────────

class AnthropicClient:
    """
    Anthropic Messages API client.

    Uses JSON prefill (assistant turn starts with '{') to guarantee JSON output
    without relying on response_format — Anthropic's recommended technique.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise ImportError("anthropic package is required: pip install anthropic>=0.30") from exc

        self._model = model or ANTHROPIC_MODEL
        self._client = Anthropic(api_key=api_key or ANTHROPIC_API_KEY or None)
        self._usage: dict[str, int] = {}

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self._usage)

    def clone(self) -> "AnthropicClient":
        return AnthropicClient(model=self._model)

    def generate_json(
        self,
        system: str,
        user: str,
        response_schema: Type[BaseModel],
    ) -> BaseModel:
        logger.debug("Calling Anthropic model=%s …", self._model)

        # Prefill with '{' so the model is forced to continue a JSON object.
        response = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            temperature=0,
            system=system,
            messages=[
                {"role": "user",      "content": user},
                {"role": "assistant", "content": "{"},
            ],
        )

        if response.usage:
            self._usage = {
                "prompt_tokens":     response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens":      response.usage.input_tokens + response.usage.output_tokens,
            }

        # Prepend the prefill character the model continued from.
        raw = "{" + (response.content[0].text if response.content else "")
        try:
            data = json.loads(raw)
            return response_schema.model_validate(data)
        except Exception as exc:
            raise ValueError(
                f"Failed to parse Anthropic response into {response_schema.__name__}.\n"
                f"Raw response:\n{raw}\nError: {exc}"
            ) from exc


# ── Factory ───────────────────────────────────────────────────────────────────

def get_client(provider: Optional[str] = None, model: Optional[str] = None) -> LLMClient:
    """Return an LLMClient for the requested provider."""
    p = (provider or LLM_PROVIDER).lower()
    if p == "openai":
        return OpenAIClient(model=model)
    if p == "anthropic":
        return AnthropicClient(model=model)
    raise NotImplementedError(
        f"LLM provider '{p}' is not implemented. Supported: openai, anthropic."
    )
