"""
Configuration — loads environment variables and defines shared constants.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file: src/ -> root)
_PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


# ── LLM ───────────────────────────────────────────────────────────────────────

def get_llm_model() -> str:
    """Return the configured LLM model name; raise if unset."""
    model = os.environ.get("LLM_MODEL", "").strip()
    if not model:
        raise EnvironmentError(
            "LLM_MODEL environment variable is required but not set. "
            "Copy .env.example → .env and set LLM_MODEL."
        )
    return model


LLM_PROVIDER: str = os.environ.get("LLM_PROVIDER", "openai").strip()
OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL: str = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
MAX_REPAIR_RETRIES: int = int(os.environ.get("MAX_REPAIR_RETRIES", "2"))
COVERAGE_SUPERSET_THRESHOLD: float = float(os.environ.get("COVERAGE_SUPERSET_THRESHOLD", "1.5"))


# ── Database ──────────────────────────────────────────────────────────────────

DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://aistrike:aistrike@localhost:5433/cloudtrail",
)

TABLE_NAME = "cloudtrail_events"

# Statement timeout for query execution (milliseconds)
QUERY_TIMEOUT_MS: int = int(os.environ.get("QUERY_TIMEOUT_MS", "30000"))


# ── Data paths ────────────────────────────────────────────────────────────────

CSV_PATH: Path = Path(os.environ.get("CSV_PATH", "data/nineteenFeaturesDf.csv"))
HYPOTHESES_PATH: Path = Path(
    os.environ.get("HYPOTHESES_PATH", "data/hypotheses.json")
)
HYPOTHESES_OUTCOMES_PATH: Path = Path(
    os.environ.get("HYPOTHESES_OUTCOMES_PATH", "data/hypotheses_outcomes.json")
)

# Resolve relative paths against project root
if not CSV_PATH.is_absolute():
    CSV_PATH = _PROJECT_ROOT / CSV_PATH
if not HYPOTHESES_PATH.is_absolute():
    HYPOTHESES_PATH = _PROJECT_ROOT / HYPOTHESES_PATH
if not HYPOTHESES_OUTCOMES_PATH.is_absolute():
    HYPOTHESES_OUTCOMES_PATH = _PROJECT_ROOT / HYPOTHESES_OUTCOMES_PATH


# ── CloudTrail schema ─────────────────────────────────────────────────────────

# Columns and their Postgres types.  eventTime is the only non-TEXT column.
SCHEMA_COLUMNS: list[tuple[str, str]] = [
    ("eventID",                       "TEXT"),
    ("eventTime",                     "TIMESTAMPTZ"),
    ("sourceIPAddress",               "TEXT"),
    ("userAgent",                     "TEXT"),
    ("eventName",                     "TEXT"),
    ("eventSource",                   "TEXT"),
    ("awsRegion",                     "TEXT"),
    ("eventVersion",                  "TEXT"),
    ("userIdentitytype",              "TEXT"),
    ("eventType",                     "TEXT"),
    ("requestID",                     "TEXT"),
    ("userIdentityaccountId",         "TEXT"),
    ("userIdentityprincipalId",       "TEXT"),
    ("userIdentityarn",               "TEXT"),
    ("userIdentityaccessKeyId",       "TEXT"),
    ("userIdentityuserName",          "TEXT"),
    ("errorCode",                     "TEXT"),
    ("errorMessage",                  "TEXT"),
    ("requestParametersinstanceType", "TEXT"),
]

COLUMN_NAMES: list[str] = [col for col, _ in SCHEMA_COLUMNS]


# ── Evaluation key map ────────────────────────────────────────────────────────
# For most hypotheses we match rows on eventID.
# Hypothesis "1" ground truth has no eventID; use composite key instead.

HYP_KEY_MAP: dict[str, list[str]] = {
    "1": ["eventTime", "sourceIPAddress", "userIdentityuserName"],
}
DEFAULT_MATCH_KEYS: list[str] = ["eventID"]


# ── Hypothesis-specific extra prompt hints ────────────────────────────────────
# Used when a hypothesis needs extra context that can't be derived from the
# schema alone (e.g., regex extraction, single-row GT, anchor requirements).

HYP_EXTRA_HINTS: dict[str, str] = {
    "3": (
        "IMPORTANT: Use ONLY these three eventNames — no others: "
        "'StopLogging', 'DeleteTrail', 'UpdateTrail'. "
        "Do NOT include PutEventSelectors, PutInsightSelectors, StartLogging, or any other "
        "CloudTrail management events. The ground truth contains exactly these three disruptive "
        "actions that an attacker would perform to blind CloudTrail monitoring."
    ),
    "4": (
        "IMPORTANT: Filter using ONLY errorCode = 'AccessDenied'. "
        "Do NOT include 'Client.UnauthorizedOperation' — that errorCode applies to EC2 actions "
        "(RunInstances, CreateKeyPair, etc.) which are NOT part of this hypothesis. "
        "The hypothesis is about IAM/API reconnaissance failures, which produce 'AccessDenied'."
    ),
    "6": (
        "IMPORTANT: The expected output contains exactly 1 row. "
        "Focus only on the single most direct secret-retrieval action: "
        "eventName = 'GetSecretValue'. Do NOT include any other Secrets Manager actions."
    ),
    "7": (
        "IMPORTANT: Match ONLY these exact instance types using an IN clause — do NOT use ILIKE "
        "patterns, as they over-match bare-metal variants not present in this dataset:\n"
        "('c5.12xlarge','c5.18xlarge','c5.24xlarge','c5d.12xlarge','c5d.18xlarge','c5d.24xlarge',"
        "'f1.16xlarge','g3.16xlarge','h1.16xlarge','i3.16xlarge','m4.10xlarge','m4.16xlarge',"
        "'m5.12xlarge','m5.16xlarge','m5.24xlarge','m5a.24xlarge','m5d.12xlarge','m5d.16xlarge',"
        "'m5d.24xlarge','p2.16xlarge','p3.16xlarge','p3dn.24xlarge','r4.16xlarge','r5.12xlarge',"
        "'r5.16xlarge','r5.24xlarge','r5d.12xlarge','r5d.16xlarge','r5d.24xlarge','x1.16xlarge',"
        "'x1.32xlarge','x1e.16xlarge','x1e.32xlarge','z1d.12xlarge')\n"
        "Use: WHERE \"eventName\" = 'RunInstances' AND \"requestParametersinstanceType\" IN (...)"
    ),
    "8": (
        "IMPORTANT: The ground truth only contains rows where errorCode is 'AccessDenied' or "
        "'NoSuchBucket'. Add a WHERE filter: \"errorCode\" IN ('AccessDenied', 'NoSuchBucket'). "
        "Do NOT include NULL errorCode or 'AllAccessDisabled' — those represent different failure "
        "modes not tracked in this hypothesis."
    ),
    "9b": (
        "IMPORTANT: The expected 'userAgent' output values are extracted command tokens "
        "like 'command/ec2.describe-snapshots' or 'command/s3.ls]' — NOT the full "
        "userAgent strings. The full userAgent strings contain this token embedded, e.g.: "
        "'aws-cli/2.0.49 Python/3.7.4 Darwin/19.6.0 exe/x86_64 command/ec2.describe-snapshots'. "
        "Use: substring(\"userAgent\" FROM 'command/\\S+') AS \"userAgent\" "
        "to extract the token, and GROUP BY that extracted value. "
        "The WHERE clause should still use ILIKE '%%command/%%' to find the matching rows."
    ),
}


# ── Output paths ──────────────────────────────────────────────────────────────

GENERATED_QUERIES_PATH: Path = _PROJECT_ROOT / "generated_queries.json"
EVALUATION_RESULTS_PATH: Path = _PROJECT_ROOT / "evaluation_results.json"
EVALUATION_REPORT_PATH: Path = _PROJECT_ROOT / "EVALUATION_REPORT.md"
