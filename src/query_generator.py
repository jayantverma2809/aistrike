"""
Query Generator — Iteration 4.

Key additions over iteration 2/3:
- `detection_gap` field in GeneratedQuery (what attack goes undetected without this query).
- Self-repair retry loop: EXPLAIN-validates generated SQL; on failure re-prompts with
  the error message up to MAX_REPAIR_RETRIES times.
- Parallel generation: generate_all() uses a ThreadPoolExecutor so all hypotheses fire
  concurrently, cutting wall-clock time ~10×.
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional, Callable

import pandas as pd
from pydantic import BaseModel, Field, field_validator

from src.config import MAX_REPAIR_RETRIES
from src.llm_client import LLMClient, get_client
from src.prompts import build_repair_prompt, build_user_prompt, get_system_prompt

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

class GeneratedQuery(BaseModel):
    """Structured output from the LLM for a single hypothesis."""

    query: str = Field(description="The complete, executable PostgreSQL SELECT statement.")
    hypothesis_interpretation: str
    query_reasoning: str
    assumptions_made: list[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    detection_gap: str = Field(
        default="",
        description=(
            "What attacker action would go completely undetected in a SIEM "
            "without this query, and why this coverage closes a real gap."
        ),
    )

    @field_validator("query")
    @classmethod
    def query_must_be_select(cls, v: str) -> str:
        stripped = v.strip().upper()
        if not stripped.startswith("SELECT"):
            raise ValueError("query must start with SELECT")
        return v.strip()

    @field_validator("confidence_score", mode="before")
    @classmethod
    def clamp_confidence(cls, v: Any) -> float:
        return max(0.0, min(1.0, float(v)))


class GeneratedQueryResult(BaseModel):
    """Wraps a GeneratedQuery with hypothesis metadata and call statistics."""

    hypothesis_id: str
    hypothesis_name: str
    hypothesis_text: str
    generated: Optional[GeneratedQuery] = None
    error: Optional[str] = None
    latency_seconds: float = 0.0
    token_usage: dict[str, int] = Field(default_factory=dict)
    repair_attempts: int = 0


# ── Generator ─────────────────────────────────────────────────────────────────

class QueryGenerator:
    """
    Translates natural-language hypotheses into executable SQL queries.

    Accepts a ground_truth dict so the LLM knows the exact expected output schema.
    Validates each query via EXPLAIN and self-repairs on failure (up to
    MAX_REPAIR_RETRIES attempts).
    """

    def __init__(
        self,
        client: Optional[LLMClient] = None,
        ground_truth: Optional[dict[str, pd.DataFrame]] = None,
        provider: Optional[str] = None,
    ):
        self._provider = provider
        self._client = client or get_client(provider)
        self._ground_truth = ground_truth or {}
        self._system_prompt = get_system_prompt()

    def _clone_for_thread(self) -> "QueryGenerator":
        """Return a fresh generator sharing ground truth and the cached system prompt."""
        clone = QueryGenerator.__new__(QueryGenerator)
        clone._provider = self._provider
        clone._client = self._client.clone()
        clone._ground_truth = self._ground_truth
        clone._system_prompt = self._system_prompt
        return clone

    def generate(self, hypothesis: dict) -> GeneratedQueryResult:
        """
        Generate (and EXPLAIN-validate) a SQL query for one hypothesis.

        On SQL validation failure, re-prompts the LLM with the error context up to
        MAX_REPAIR_RETRIES times before giving up.
        """
        from src.db import run_query  # local import to avoid circular at module load

        hyp_id   = str(hypothesis.get("id", "unknown"))
        hyp_name = hypothesis.get("name", "")
        hyp_text = hypothesis.get("hypothesis", "")

        result = GeneratedQueryResult(
            hypothesis_id=hyp_id,
            hypothesis_name=hyp_name,
            hypothesis_text=hyp_text,
        )

        expected_df = self._ground_truth.get(hyp_id)
        current_user_prompt = build_user_prompt(hypothesis, expected_df=expected_df)
        logger.debug("[HYP-%s] User prompt:\n%s", hyp_id, current_user_prompt)

        t0 = time.time()
        generated: Optional[GeneratedQuery] = None

        for attempt in range(MAX_REPAIR_RETRIES + 1):
            # ── LLM call ──────────────────────────────────────────────────────
            try:
                generated = self._client.generate_json(
                    system=self._system_prompt,
                    user=current_user_prompt,
                    response_schema=GeneratedQuery,
                )
                result.token_usage = self._client.last_usage
            except Exception as llm_err:
                logger.error("[HYP-%s] LLM call failed (attempt %d): %s", hyp_id, attempt + 1, llm_err)
                result.error = str(llm_err)
                break

            # ── SQL validation via EXPLAIN ─────────────────────────────────────
            try:
                run_query(f"EXPLAIN {generated.query}")
                # Valid SQL — commit result
                result.generated = generated
                result.repair_attempts = attempt
                if attempt > 0:
                    logger.info(
                        "[HYP-%s] SQL repaired successfully on attempt %d/%d",
                        hyp_id, attempt + 1, MAX_REPAIR_RETRIES + 1,
                    )
                break
            except Exception as sql_err:
                err_str = str(sql_err)
                if attempt < MAX_REPAIR_RETRIES:
                    logger.warning(
                        "[HYP-%s] EXPLAIN failed (attempt %d/%d): %s — requesting repair",
                        hyp_id, attempt + 1, MAX_REPAIR_RETRIES + 1, err_str,
                    )
                    current_user_prompt = build_repair_prompt(
                        current_user_prompt, generated.query, err_str
                    )
                else:
                    logger.error(
                        "[HYP-%s] SQL validation failed after %d attempt(s). Last error: %s",
                        hyp_id, attempt + 1, err_str,
                    )
                    result.error = (
                        f"SQL validation failed after {attempt + 1} attempt(s): {err_str}"
                    )

        result.latency_seconds = time.time() - t0

        if result.generated:
            logger.info(
                "[HYP-%s] Generated SQL (conf=%.2f, tokens=%d, repairs=%d):\n%s",
                hyp_id,
                result.generated.confidence_score,
                result.token_usage.get("total_tokens", 0),
                result.repair_attempts,
                result.generated.query,
            )
        else:
            logger.info("[HYP-%s] FAILED in %.2fs — %s", hyp_id, result.latency_seconds, result.error)

        return result

    def generate_all(
        self,
        hypotheses: list[dict],
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> list[GeneratedQueryResult]:
        """
        Generate queries for all hypotheses in parallel (one thread per hypothesis).

        Each thread gets its own LLM client clone to avoid shared usage-state races.
        Results are returned in the same order as the input hypotheses list.
        """
        results: list[Optional[GeneratedQueryResult]] = [None] * len(hypotheses)

        def _one(args: tuple[int, dict]) -> tuple[int, GeneratedQueryResult]:
            idx, hyp = args
            return idx, self._clone_for_thread().generate(hyp)

        with ThreadPoolExecutor(max_workers=len(hypotheses)) as pool:
            futures = {pool.submit(_one, (i, h)): i for i, h in enumerate(hypotheses)}
            completed = 0
            for future in as_completed(futures):
                idx, res = future.result()
                results[idx] = res
                completed += 1
                if progress_cb:
                    progress_cb(completed, len(hypotheses), f"Generated query for hypothesis {res.hypothesis_id}")

        return results  # type: ignore[return-value]


# ── Serialization ─────────────────────────────────────────────────────────────

def results_to_json(results: list[GeneratedQueryResult], path: Path) -> None:
    data = [r.model_dump() for r in results]
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    logger.info("Generated queries written to %s", path)


def results_from_json(path: Path) -> list[GeneratedQueryResult]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [GeneratedQueryResult.model_validate(item) for item in data]
