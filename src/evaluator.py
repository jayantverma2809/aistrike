"""
Evaluation framework — Iteration 4.

Ground truth types (auto-detected):
  A  has 'eventID'   → match on eventID
  B  composite-key   → match on all GT columns
  C  aggregated      → has 'count'; match on key columns

New in iteration 4:
- detection_gap forwarded from GeneratedQuery into HypothesisScore.
- Extended Coverage Score: when recall=1.0 and the query returns significantly
  more rows than expected, an LLM-as-judge call decides whether the extra rows
  are legitimate in-class detections (extended_coverage=True) or real false
  positives.  This turns "over-detection" into a positive signal instead of a
  penalty.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional, Callable

import pandas as pd
from pydantic import BaseModel, Field

from src.config import (
    COVERAGE_SUPERSET_THRESHOLD,
    EVALUATION_REPORT_PATH,
    EVALUATION_RESULTS_PATH,
)
from src.db import run_query
from src.query_generator import GeneratedQueryResult

logger = logging.getLogger(__name__)


# ── Ground truth type detection ───────────────────────────────────────────────

def _gt_type(expected: pd.DataFrame) -> str:
    if "eventID" in expected.columns:
        return "A"
    if "count" in expected.columns:
        return "C"
    return "B"


def _match_keys_for(hyp_id: str, expected: pd.DataFrame) -> list[str]:
    gt_type = _gt_type(expected)
    if gt_type == "A":
        return ["eventID"]
    if gt_type == "C":
        return [c for c in expected.columns if c != "count"]
    return list(expected.columns)


# ── Result models ─────────────────────────────────────────────────────────────

class HypothesisScore(BaseModel):
    hypothesis_id: str
    hypothesis_name: str
    gt_type: str = ""
    match_keys: list[str] = Field(default_factory=list)
    query_executed_ok: bool
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    row_count_returned: int = 0
    row_count_expected: int = 0
    error: Optional[str] = None
    latency_seconds: float = 0.0
    sql_query: Optional[str] = None
    hypothesis_interpretation: Optional[str] = None
    query_reasoning: Optional[str] = None
    assumptions_made: list[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None
    detection_gap: str = ""
    # Coverage scoring
    extended_coverage: bool = False
    coverage_verdict: str = ""


class EvaluationReport(BaseModel):
    model_name: str = "unknown"
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0
    queries_executed_ok: int = 0
    total_hypotheses: int = 0
    total_latency_seconds: float = 0.0
    total_tokens: int = 0
    hypotheses: list[HypothesisScore] = Field(default_factory=list)


# ── Scoring helpers ───────────────────────────────────────────────────────────

def _normalize_timestamps(series: pd.Series) -> pd.Series:
    try:
        parsed = pd.to_datetime(series, utc=True)
        return parsed.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return series.fillna("").astype(str)


def _to_tuple_set(df: pd.DataFrame, keys: list[str]) -> set[tuple]:
    available = [k for k in keys if k in df.columns]
    if not available:
        return set()
    sub = df[available].copy()
    for col in available:
        if pd.api.types.is_datetime64_any_dtype(sub[col]) or col.lower().endswith("time"):
            sub[col] = _normalize_timestamps(sub[col])
    return set(sub.fillna("").astype(str).itertuples(index=False, name=None))


def score(
    expected: pd.DataFrame,
    actual: pd.DataFrame,
    hyp_id: str,
) -> dict[str, Any]:
    gt_type = _gt_type(expected)
    keys = _match_keys_for(hyp_id, expected)

    logger.info(
        "[HYP-%s] GT type=%s  match_keys=%s  expected=%d rows  actual=%d rows",
        hyp_id, gt_type, keys, len(expected), len(actual),
    )

    if expected.empty:
        logger.warning("[HYP-%s] No ground truth available — marking as unscored.", hyp_id)
        return {
            "gt_type": gt_type, "match_keys": keys,
            "true_positives": 0, "false_positives": 0, "false_negatives": 0,
            "precision": None, "recall": None, "f1": None,
            "row_count_expected": 0, "row_count_returned": len(actual),
            "unscored": True,
        }

    expected_set = _to_tuple_set(expected, keys)
    actual_set   = _to_tuple_set(actual,   keys)

    tp = len(expected_set & actual_set)
    fp = len(actual_set   - expected_set)
    fn = len(expected_set - actual_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)

    fp_keys = actual_set - expected_set
    if fp_keys:
        logger.info("[HYP-%s] Sample FP key tuples: %s", hyp_id, list(fp_keys)[:3])

    fn_keys = expected_set - actual_set
    if fn_keys:
        logger.info("[HYP-%s] Sample FN key tuples: %s", hyp_id, list(fn_keys)[:3])

    logger.info(
        "[HYP-%s] TP=%d  FP=%d  FN=%d  P=%.4f  R=%.4f  F1=%.4f",
        hyp_id, tp, fp, fn, precision, recall, f1,
    )

    return {
        "gt_type": gt_type, "match_keys": keys,
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "row_count_expected": len(expected), "row_count_returned": len(actual),
        "unscored": False,
        # Pass sets through for coverage scoring
        "_actual_set": actual_set, "_expected_set": expected_set,
    }


# ── LLM-as-judge: extended coverage ──────────────────────────────────────────

def _judge_extended_coverage(
    hyp_id: str,
    hyp_text: str,
    fp_rows: list[dict],
    client: Any,
) -> tuple[bool, str]:
    """
    Ask an LLM whether the extra rows a query returned (beyond ground truth)
    are legitimate in-class detections for the stated hypothesis, or noise.

    Returns (is_extended_coverage, rationale).
    """
    from pydantic import BaseModel as _BM

    class _Judgment(_BM):
        is_extended_coverage: bool
        coverage_rationale: str

    system = (
        "You are a cloud security expert evaluating threat detection coverage.\n\n"
        "You will be given a threat hypothesis and a sample of database rows that a detection query returned but that are NOT in the expected ground truth.\n\n"
        "Decide: are these extra rows LEGITIMATE IN-CLASS DETECTIONS for the stated threat (i.e., they represent the same class of attacker behaviour, just more instances than the curated ground truth), or are they FALSE POSITIVES (unrelated events that happen to match the query)?\n\n"
        'Respond with JSON: {"is_extended_coverage": true/false, "coverage_rationale": "one or two sentences explaining your verdict"}'
    )

    user = (
        f"## Threat Hypothesis\n{hyp_text}\n\n"
        f"## Sample Extra Rows (returned by query but absent from ground truth)\n"
        f"{json.dumps(fp_rows, indent=2, default=str)}\n\n"
        "Are these extra rows legitimate in-class detections for this threat?"
    )

    try:
        judgment = client.generate_json(system, user, _Judgment)
        logger.info(
            "[HYP-%s] Coverage judge: extended_coverage=%s — %s",
            hyp_id, judgment.is_extended_coverage, judgment.coverage_rationale,
        )
        return judgment.is_extended_coverage, judgment.coverage_rationale
    except Exception as exc:
        logger.warning("[HYP-%s] Coverage judge failed: %s", hyp_id, exc)
        return False, f"Coverage judge unavailable: {exc}"


def _get_fp_sample(
    actual_df: pd.DataFrame,
    keys: list[str],
    expected_set: set,
    actual_set: set,
    n: int = 5,
) -> list[dict]:
    """Return up to n rows from actual_df whose key tuple is in (actual - expected)."""
    fp_set = actual_set - expected_set
    if not fp_set or actual_df.empty:
        return []
    available_keys = [k for k in keys if k in actual_df.columns]
    if not available_keys:
        return actual_df.head(n).to_dict(orient="records")
    sub = actual_df[available_keys].copy()
    for col in available_keys:
        if pd.api.types.is_datetime64_any_dtype(sub[col]) or col.lower().endswith("time"):
            sub[col] = _normalize_timestamps(sub[col])
    mask = sub.fillna("").astype(str).apply(tuple, axis=1).isin(fp_set)
    return actual_df[mask].head(n).to_dict(orient="records")


# ── Evaluator ─────────────────────────────────────────────────────────────────

class Evaluator:
    """
    Executes generated SQL queries and scores them against ground truth.

    Pass client to enable the LLM-as-judge extended coverage scoring.
    """

    def __init__(self, ground_truth: dict[str, pd.DataFrame], client: Any = None):
        self._gt = ground_truth
        self._client = client

    def evaluate_one(self, result: GeneratedQueryResult) -> HypothesisScore:
        hyp_id = result.hypothesis_id
        hs = HypothesisScore(
            hypothesis_id=hyp_id,
            hypothesis_name=result.hypothesis_name,
            query_executed_ok=False,
        )

        if result.generated:
            hs.sql_query                 = result.generated.query
            hs.hypothesis_interpretation = result.generated.hypothesis_interpretation
            hs.query_reasoning           = result.generated.query_reasoning
            hs.assumptions_made          = result.generated.assumptions_made
            hs.confidence_score          = result.generated.confidence_score
            hs.detection_gap             = result.generated.detection_gap

        if result.error or not result.generated:
            hs.error = result.error or "No query was generated."
            logger.error("[HYP-%s] Generation error: %s", hyp_id, hs.error)
            return hs

        sql = result.generated.query
        logger.info("[HYP-%s] Executing SQL:\n%s", hyp_id, sql)

        t0 = time.time()
        try:
            actual_df = run_query(sql)
            hs.query_executed_ok = True
        except Exception as exc:
            hs.error = f"Query execution error: {exc}"
            hs.latency_seconds = time.time() - t0
            logger.error("[HYP-%s] Execution FAILED: %s", hyp_id, exc)
            return hs

        hs.latency_seconds = time.time() - t0
        logger.info("[HYP-%s] Query returned %d rows in %.2fs", hyp_id, len(actual_df), hs.latency_seconds)

        expected_df = self._gt.get(hyp_id, pd.DataFrame())
        metrics = score(expected_df, actual_df, hyp_id)

        hs.gt_type            = metrics["gt_type"]
        hs.match_keys         = metrics["match_keys"]
        hs.true_positives     = metrics["true_positives"]
        hs.false_positives    = metrics["false_positives"]
        hs.false_negatives    = metrics["false_negatives"]
        hs.row_count_expected = metrics["row_count_expected"]
        hs.row_count_returned = metrics["row_count_returned"]

        if metrics.get("unscored"):
            hs.precision = hs.recall = hs.f1 = -1.0
        else:
            hs.precision = metrics["precision"]
            hs.recall    = metrics["recall"]
            hs.f1        = metrics["f1"]

        # ── Extended coverage check ───────────────────────────────────────────
        # Trigger when: recall=1.0, there are FPs, and result is meaningfully
        # larger than expected (suggesting the query catches MORE real threats).
        if (
            self._client is not None
            and not metrics.get("unscored")
            and hs.recall == 1.0
            and hs.false_positives > 0
            and hs.row_count_expected > 0
            and hs.row_count_returned > hs.row_count_expected * COVERAGE_SUPERSET_THRESHOLD
        ):
            logger.info(
                "[HYP-%s] Coverage check triggered (returned %d vs expected %d, threshold ×%.1f)",
                hyp_id, hs.row_count_returned, hs.row_count_expected, COVERAGE_SUPERSET_THRESHOLD,
            )
            fp_sample = _get_fp_sample(
                actual_df,
                metrics["match_keys"],
                metrics.get("_expected_set", set()),
                metrics.get("_actual_set", set()),
            )
            is_coverage, verdict = _judge_extended_coverage(
                hyp_id=hyp_id,
                hyp_text=result.hypothesis_text,
                fp_rows=fp_sample,
                client=self._client,
            )
            hs.extended_coverage = is_coverage
            hs.coverage_verdict  = verdict

        return hs

    def evaluate_all(
        self,
        query_results: list[GeneratedQueryResult],
        token_totals: dict[str, int] | None = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        model_name: str = "unknown",
    ) -> EvaluationReport:
        scores: list[HypothesisScore] = []
        total_latency = 0.0

        for i, qr in enumerate(query_results):
            hs = self.evaluate_one(qr)
            hs.latency_seconds += qr.latency_seconds
            scores.append(hs)
            if progress_cb:
                progress_cb(i + 1, len(query_results), f"Evaluated hypothesis {qr.hypothesis_id}")
            total_latency += hs.latency_seconds

        scored = [s for s in scores if s.query_executed_ok and s.f1 >= 0]
        n = len(scored)
        macro_p  = sum(s.precision for s in scored) / n if n else 0.0
        macro_r  = sum(s.recall    for s in scored) / n if n else 0.0
        macro_f1 = sum(s.f1        for s in scored) / n if n else 0.0

        logger.info(
            "=== MACRO (over %d scored hypotheses) ===  P=%.4f  R=%.4f  F1=%.4f",
            n, macro_p, macro_r, macro_f1,
        )

        return EvaluationReport(
            model_name=model_name,
            macro_precision=round(macro_p,  4),
            macro_recall=round(macro_r,     4),
            macro_f1=round(macro_f1,        4),
            queries_executed_ok=sum(1 for s in scores if s.query_executed_ok),
            total_hypotheses=len(scores),
            total_latency_seconds=round(total_latency, 2),
            total_tokens=(token_totals or {}).get("total_tokens", 0),
            hypotheses=scores,
        )


# ── Persistence ───────────────────────────────────────────────────────────────

def save_evaluation_results(report: EvaluationReport, path: Path | None = None) -> None:
    out = path or EVALUATION_RESULTS_PATH
    out.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")
    logger.info("Evaluation results written to %s", out)


def generate_markdown_report(
    report: EvaluationReport,
    path: Path | None = None,
) -> str:
    from tabulate import tabulate

    lines: list[str] = []
    lines += ["# Evaluation Report", "", "## Summary", ""]

    summary_rows = [
        ["Model Used",          report.model_name],
        ["Macro Precision",     f"{report.macro_precision:.4f}"],
        ["Macro Recall",        f"{report.macro_recall:.4f}"],
        ["Macro F1",            f"{report.macro_f1:.4f}"],
        ["Queries Executed OK", f"{report.queries_executed_ok} / {report.total_hypotheses}"],
        ["Total Latency (s)",   f"{report.total_latency_seconds:.1f}"],
        ["Total Tokens Used",   str(report.total_tokens)],
    ]
    lines.append(tabulate(summary_rows, headers=["Metric", "Value"], tablefmt="github"))
    lines.append("")

    lines += ["## Per-Hypothesis Results", ""]

    table_rows = []
    for hs in report.hypotheses:
        ok  = "✅" if hs.query_executed_ok else "❌"
        p   = f"{hs.precision:.3f}" if hs.precision  >= 0 else "N/A"
        r   = f"{hs.recall:.3f}"    if hs.recall     >= 0 else "N/A"
        f1  = f"{hs.f1:.3f}"        if hs.f1         >= 0 else "N/A"
        cov = "🔍 extended" if hs.extended_coverage else ""
        table_rows.append([
            hs.hypothesis_id, hs.hypothesis_name, hs.gt_type, ok,
            p, r, f1,
            hs.row_count_returned, hs.row_count_expected,
            f"{hs.latency_seconds:.1f}s", cov,
        ])

    lines.append(tabulate(
        table_rows,
        headers=["ID", "Hypothesis", "GT Type", "OK?", "P", "R", "F1",
                 "Returned", "Expected", "Time", "Coverage"],
        tablefmt="github",
    ))
    lines.append("")

    lines += ["## Detailed Breakdown", ""]

    for hs in report.hypotheses:
        lines += [f"### Hypothesis {hs.hypothesis_id}: {hs.hypothesis_name}", ""]
        if hs.gt_type:
            lines.append(f"**GT Type:** {hs.gt_type}  |  **Match Keys:** `{hs.match_keys}`")
            lines.append("")
        if hs.error:
            lines += [f"> **ERROR:** {hs.error}", ""]
        if hs.hypothesis_interpretation:
            lines += [
                f"**Interpretation:** {hs.hypothesis_interpretation}", "",
                f"**Query Reasoning:** {hs.query_reasoning}", "",
            ]
        if hs.detection_gap:
            lines += [
                "**Detection Gap:**",
                f"> {hs.detection_gap}",
                "",
            ]
        if hs.assumptions_made:
            lines += ["**Assumptions:**"]
            for a in hs.assumptions_made:
                lines.append(f"- {a}")
            lines.append("")
        if hs.confidence_score is not None:
            lines.append(f"**Confidence Score:** {hs.confidence_score:.2f}")
            lines.append("")
        if hs.sql_query:
            lines += ["**Generated SQL:**", "", "```sql", hs.sql_query, "```", ""]
        if hs.query_executed_ok:
            if hs.f1 < 0:
                lines.append("**Score:** N/A (no ground truth)")
            else:
                lines += [
                    f"- **Precision:** {hs.precision:.4f}",
                    f"- **Recall:** {hs.recall:.4f}",
                    f"- **F1 Score:** {hs.f1:.4f}",
                    f"- **Counts:** TP={hs.true_positives}, FP={hs.false_positives}, FN={hs.false_negatives}"
                ]
            lines.append("")
            if hs.extended_coverage:
                lines += [
                    "**🔍 Extended Coverage Detected:**",
                    f"> {hs.coverage_verdict}",
                    "",
                    "_Note: FP count reflects rows beyond the curated ground truth, "
                    "not necessarily detection errors. The query may be catching more "
                    "real-world instances of this threat than the ground truth recorded._",
                    "",
                ]
            elif hs.coverage_verdict:
                lines += [
                    f"**Coverage Verdict:** {hs.coverage_verdict}",
                    "",
                ]
        if hs.f1 >= 0 and hs.f1 < 1.0 and hs.query_executed_ok and not hs.extended_coverage:
            lines.append("**Failure Note:** F1 < 1.0 — review false positives/negatives above.")
            lines.append("")
        lines += ["---", ""]

    md = "\n".join(lines)
    out = path or EVALUATION_REPORT_PATH
    out.write_text(md, encoding="utf-8")
    logger.info("Evaluation report written to %s", out)
    return md
