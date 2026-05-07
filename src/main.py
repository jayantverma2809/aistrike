"""
Entry point — CLI for the AI Threat Hunting Query Generation & Evaluation System.

Subcommands:
  ingest    — Load CSV into PostgreSQL (idempotent).
  generate  — Run LLM query generation for all hypotheses (parallel).
  evaluate  — Execute queries, score against ground truth, write reports.
  all       — Run ingest → generate → evaluate in sequence.

Usage:
  python -m src.main [ingest|generate|evaluate|all] [--iter N] [--providers P1[,P2]] [--force-ingest]

  --iter N              Tag this run as iteration N.
                        Results are saved to results/iter{N}_*.
  --providers P1[,P2]   Comma-separated LLM providers (e.g., openai or openai,anthropic).
                        When multiple, A/B comparison is run and results saved with
                        a provider suffix: iter{N}_{provider}_*.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_hypotheses(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_ground_truth(outcomes_path):
    import importlib.util as ilu
    data_utils_path = Path(__file__).parent.parent / "data" / "utils.py"
    spec = ilu.spec_from_file_location("data_utils", data_utils_path)
    data_utils = ilu.module_from_spec(spec)
    spec.loader.exec_module(data_utils)
    return data_utils.load_hypotheses_outcomes(str(outcomes_path))


def _get_providers(args: argparse.Namespace) -> list[str]:
    """Parse --providers flag; fall back to LLM_PROVIDER env var."""
    raw = getattr(args, "providers", None) or os.environ.get("LLM_PROVIDER", "openai")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _results_paths(
    iteration: int | None,
    provider: str | None = None,
) -> dict[str, Path]:
    """
    Return output paths for the given iteration + provider tag.

    provider suffix is added only when explicitly passed (A/B mode).
    When iteration is None, return the default top-level paths only.
    """
    from src.config import (
        EVALUATION_REPORT_PATH,
        EVALUATION_RESULTS_PATH,
        GENERATED_QUERIES_PATH,
    )
    primary = {
        "generated_queries":  GENERATED_QUERIES_PATH,
        "evaluation_results": EVALUATION_RESULTS_PATH,
        "evaluation_report":  EVALUATION_REPORT_PATH,
    }
    if iteration is None:
        return primary

    results_dir = Path(__file__).parent.parent / "results"
    results_dir.mkdir(exist_ok=True)
    prov = f"_{provider}" if provider else ""
    tagged = {
        "generated_queries":  results_dir / f"iter{iteration}{prov}_generated_queries.json",
        "evaluation_results": results_dir / f"iter{iteration}{prov}_evaluation_results.json",
        "evaluation_report":  results_dir / f"iter{iteration}{prov}_EVALUATION_REPORT.md",
    }
    return {"primary": primary, "tagged": tagged}


def _save_to_all(content: str | bytes, paths: dict, key: str) -> None:
    """Write content to tagged path only (when --iter given), or primary path otherwise."""
    data = content if isinstance(content, bytes) else content.encode()
    if "primary" in paths:
        # --iter N supplied: write only to results/iter{N}_*
        paths["tagged"][key].write_bytes(data)
        logger.info("Saved %s → %s", key, paths["tagged"][key])
    else:
        paths[key].write_bytes(data)
        logger.info("Saved %s → %s", key, paths[key])


def _queries_path_for(args: argparse.Namespace, provider: str | None) -> Path:
    """Return the generated_queries path to load during evaluate."""
    iteration = getattr(args, "iter", None)
    paths = _results_paths(iteration, provider)
    if "primary" in paths:
        return paths["tagged"]["generated_queries"]
    return paths["generated_queries"]


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_ingest(args: argparse.Namespace) -> int:
    from src.config import CSV_PATH
    from src.db import ingest_csv

    logger.info("=== INGEST ===")
    count = ingest_csv(CSV_PATH, force=getattr(args, "force_ingest", False))
    print(f"✓ Table contains {count:,} rows.")
    return 0


def _run_generate_for_provider(
    provider: str,
    hypotheses: list[dict],
    ground_truth: dict,
    args: argparse.Namespace,
    multi: bool,
) -> list:
    """Generate queries for a single provider and save results."""
    from src.llm_client import get_client
    from src.query_generator import QueryGenerator

    logger.info("=== GENERATE [provider=%s] ===", provider)
    client = get_client(provider)
    generator = QueryGenerator(client=client, ground_truth=ground_truth, provider=provider)
    results = generator.generate_all(hypotheses)

    iteration = getattr(args, "iter", None)
    prov_tag = provider if multi else None
    paths = _results_paths(iteration, prov_tag)

    import json as _json
    data = _json.dumps([r.model_dump() for r in results], indent=2, default=str)
    _save_to_all(data, paths, "generated_queries")
    return results


def cmd_generate(args: argparse.Namespace) -> int:
    from src.config import HYPOTHESES_OUTCOMES_PATH, HYPOTHESES_PATH

    logger.info("=== GENERATE ===")
    hypotheses = _load_hypotheses(HYPOTHESES_PATH)
    logger.info("Loaded %d hypotheses.", len(hypotheses))
    ground_truth = _load_ground_truth(HYPOTHESES_OUTCOMES_PATH)
    logger.info("Loaded ground truth for %d hypotheses.", len(ground_truth))

    providers = _get_providers(args)
    multi = len(providers) > 1

    provider_results: dict[str, list] = {}
    for provider in providers:
        provider_results[provider] = _run_generate_for_provider(
            provider, hypotheses, ground_truth, args, multi
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    iteration = getattr(args, "iter", None)
    tag = f" (iter {iteration})" if iteration else ""

    if multi:
        print(f"\n{'='*52}")
        print(f"  A/B GENERATION SUMMARY{tag}")
        print(f"{'='*52}")
        for provider, results in provider_results.items():
            ok = sum(1 for r in results if r.generated)
            failed = len(results) - ok
            tokens = sum(r.token_usage.get("total_tokens", 0) for r in results)
            print(f"  {provider:12s}: {ok}/{len(results)} generated  ({failed} failed)  {tokens:,} tokens")
        print(f"{'='*52}")
    else:
        results = list(provider_results.values())[0]
        ok = sum(1 for r in results if r.generated)
        failed = len(results) - ok
        tokens = sum(r.token_usage.get("total_tokens", 0) for r in results)
        print(f"✓ Generated {ok}/{len(results)} queries  ({failed} failed){tag}.")
        print(f"  Total tokens used: {tokens:,}")

    total_failed = sum(
        sum(1 for r in res if not r.generated)
        for res in provider_results.values()
    )
    return 0 if total_failed == 0 else 1


def _run_evaluate_for_provider(
    provider: str | None,
    args: argparse.Namespace,
    multi: bool,
) -> tuple[any, Path]:  # (EvaluationReport, report_path)
    from src.config import HYPOTHESES_OUTCOMES_PATH
    from src.evaluator import Evaluator, generate_markdown_report, save_evaluation_results
    from src.llm_client import get_client
    from src.query_generator import results_from_json

    queries_path = _queries_path_for(args, provider if multi else None)
    if not queries_path.exists():
        logger.error("Generated queries file not found: %s", queries_path)
        return None, queries_path

    query_results = results_from_json(queries_path)
    ground_truth  = _load_ground_truth(HYPOTHESES_OUTCOMES_PATH)
    logger.info(
        "[provider=%s] Loaded %d generated queries, %d ground-truth sets.",
        provider or "default", len(query_results), len(ground_truth),
    )

    total_tokens = sum(r.token_usage.get("total_tokens", 0) for r in query_results)
    client = get_client(provider) if provider else get_client()
    evaluator = Evaluator(ground_truth, client=client)
    report = evaluator.evaluate_all(query_results, {"total_tokens": total_tokens})

    iteration = getattr(args, "iter", None)
    prov_tag = provider if multi else None
    paths = _results_paths(iteration, prov_tag)

    import json as _json
    results_data = _json.dumps(report.model_dump(), indent=2, default=str)
    _save_to_all(results_data, paths, "evaluation_results")

    if iteration and "tagged" in paths:
        report_path = paths["tagged"]["evaluation_report"]
        generate_markdown_report(report, path=report_path)
    else:
        report_path = paths.get("evaluation_report")
        generate_markdown_report(report)

    return report, report_path


def cmd_evaluate(args: argparse.Namespace) -> int:
    logger.info("=== EVALUATE ===")

    providers = _get_providers(args)
    multi = len(providers) > 1
    iteration = getattr(args, "iter", None)
    tag = f" (iter {iteration})" if iteration else ""

    reports: dict[str, any] = {}
    for provider in providers:
        report, _ = _run_evaluate_for_provider(provider, args, multi)
        if report is None:
            return 1
        reports[provider] = report

    if multi:
        # A/B comparison table
        print(f"\n{'='*60}")
        print(f"  A/B EVALUATION COMPARISON{tag}")
        print(f"{'='*60}")
        print(f"  {'Provider':12s}  {'Macro P':>8}  {'Macro R':>8}  {'Macro F1':>8}  {'OK':>6}  {'Tokens':>10}")
        print(f"  {'-'*58}")
        for prov, rep in reports.items():
            print(
                f"  {prov:12s}  {rep.macro_precision:8.4f}  {rep.macro_recall:8.4f}  "
                f"{rep.macro_f1:8.4f}  {rep.queries_executed_ok:2}/{rep.total_hypotheses:2}  "
                f"{rep.total_tokens:10,}"
            )
        print(f"{'='*60}")
    else:
        report = list(reports.values())[0]
        print(f"\n{'='*52}")
        print(f"  EVALUATION SUMMARY{tag}")
        print(f"{'='*52}")
        print(f"  Macro Precision : {report.macro_precision:.4f}")
        print(f"  Macro Recall    : {report.macro_recall:.4f}")
        print(f"  Macro F1        : {report.macro_f1:.4f}")
        print(f"  Executed OK     : {report.queries_executed_ok}/{report.total_hypotheses}")
        print(f"  Total Latency   : {report.total_latency_seconds:.1f}s")
        print(f"{'='*52}")
        if iteration:
            print(f"\n  Results → results/iter{iteration}_evaluation_results.json")
            print(f"  Report  → results/iter{iteration}_EVALUATION_REPORT.md")

    return 0


def cmd_all(args: argparse.Namespace) -> int:
    logger.info("=== ALL (ingest → generate → evaluate) ===")
    rc = cmd_ingest(args)
    if rc != 0:
        return rc
    rc = cmd_generate(args)
    if rc not in (0, 1):
        return rc
    return cmd_evaluate(args)


# ── CLI wiring ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aistrike",
        description="AI Threat Hunting Query Generation & Evaluation System",
    )
    parser.add_argument(
        "--iter", type=int, default=None, metavar="N",
        help="Tag this run as iteration N; results saved to results/iter{N}_*.",
    )
    parser.add_argument(
        "--providers", type=str, default=None, metavar="P1[,P2]",
        help=(
            "Comma-separated LLM providers (e.g., openai or openai,anthropic). "
            "When multiple, A/B comparison results are saved with a provider suffix. "
            "Default: LLM_PROVIDER env var."
        ),
    )
    parser.add_argument(
        "--force-ingest", action="store_true",
        help="Truncate and reload the CSV even if rows already exist.",
    )

    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("ingest",   help="Load CSV into PostgreSQL.")
    subs.add_parser("generate", help="Generate SQL queries via LLM (parallel).")
    subs.add_parser("evaluate", help="Execute queries and score results.")
    subs.add_parser("all",      help="Run ingest → generate → evaluate.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "ingest":   cmd_ingest,
        "generate": cmd_generate,
        "evaluate": cmd_evaluate,
        "all":      cmd_all,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
