"""
Prompt templates for the query generator — Iteration 2.

Key changes from iteration 1:
- Data dictionary (real column values from the DB) injected into system prompt.
- Per-hypothesis expected output schema passed in the user prompt so the LLM
  knows exactly what columns to SELECT and whether to GROUP BY.
- Hypothesis id/name removed from the user prompt (just the description text).
"""

from __future__ import annotations

import logging

from src.config import HYP_EXTRA_HINTS, TABLE_NAME

logger = logging.getLogger(__name__)


# ── System prompt (base, without data dictionary) ─────────────────────────────

_SYSTEM_BASE = f"""\
You are a senior threat hunter and database engineer.
Your task is to translate a natural-language threat-hunting hypothesis into a
precise, executable PostgreSQL SELECT query against the CloudTrail log table
described below.

## Table schema
Table name: {TABLE_NAME}

Columns (all TEXT unless noted):
  "eventID"                       TEXT
  "eventTime"                     TIMESTAMPTZ  (ISO-8601 strings in the data)
  "sourceIPAddress"               TEXT
  "userAgent"                     TEXT
  "eventName"                     TEXT
  "eventSource"                   TEXT
  "awsRegion"                     TEXT
  "eventVersion"                  TEXT
  "userIdentitytype"              TEXT
  "eventType"                     TEXT
  "requestID"                     TEXT
  "userIdentityaccountId"         TEXT
  "userIdentityprincipalId"       TEXT
  "userIdentityarn"               TEXT
  "userIdentityaccessKeyId"       TEXT
  "userIdentityuserName"          TEXT
  "errorCode"                     TEXT
  "errorMessage"                  TEXT
  "requestParametersinstanceType" TEXT

## SQL rules
1. Write a valid PostgreSQL SELECT statement only — no DDL, DML, or procedural code.
2. Column names are case-sensitive and MUST be double-quoted exactly as shown above.
3. Use exact string values from the Data Dictionary section below; do NOT invent or
   guess column values.
4. Use ILIKE or LOWER() only for free-text fields (userAgent, errorMessage) where
   partial/case-insensitive matching is appropriate. For enumerated fields like
   eventName, userIdentitytype, eventSource, errorCode — use exact equality (=) with
   the values listed in the Data Dictionary.
5. Do NOT add a LIMIT clause unless the hypothesis explicitly scopes by count.
6. Follow the Output schema instruction exactly: if it says GROUP BY, do it; if it
   specifies exact column names (including aliases), use them.

{{DATA_DICTIONARY}}

## Output format
Respond with a single JSON object matching this exact schema:

{{{{
  "query": "<the full SELECT SQL statement>",
  "hypothesis_interpretation": "<what threat behaviour this hypothesis is asking for>",
  "query_reasoning": "<why you structured the WHERE / GROUP BY this way>",
  "assumptions_made": ["<assumption 1>", "<assumption 2>"],
  "confidence_score": <float 0.0–1.0>,
  "detection_gap": "<what attacker action would go completely undetected in a SIEM without this query, and why this coverage closes a real gap — be specific about the attack technique and the blind spot>"
}}}}

Do not include any text outside the JSON object.
"""

# ── Data dictionary builder ───────────────────────────────────────────────────

def build_data_dictionary(engine=None) -> str:
    """
    Query the DB for distinct values in key columns and return a formatted string
    for injection into the system prompt.

    Falls back to a static placeholder if the DB is unavailable.
    """
    try:
        from src.db import run_query
        sections: list[str] = ["## Data Dictionary", ""]

        # eventName top 50
        df = run_query(
            'SELECT "eventName", count(*) as n FROM cloudtrail_events '
            'GROUP BY "eventName" ORDER BY n DESC LIMIT 50'
        )
        vals = ", ".join(repr(r) for r in df["eventName"].tolist())
        sections.append(f"**eventName** (top 50 by frequency): {vals}")
        sections.append("")

        # userIdentitytype all values
        df = run_query(
            'SELECT "userIdentitytype", count(*) as n FROM cloudtrail_events '
            'GROUP BY "userIdentitytype" ORDER BY n DESC'
        )
        vals = ", ".join(repr(r) for r in df["userIdentitytype"].tolist())
        sections.append(f"**userIdentitytype** (all values): {vals}")
        sections.append("")

        # eventSource top 15
        df = run_query(
            'SELECT "eventSource", count(*) as n FROM cloudtrail_events '
            'GROUP BY "eventSource" ORDER BY n DESC LIMIT 15'
        )
        vals = ", ".join(repr(r) for r in df["eventSource"].tolist())
        sections.append(f"**eventSource** (top 15): {vals}")
        sections.append("")

        # errorCode top 20 (non-null/non-empty)
        df = run_query(
            'SELECT "errorCode", count(*) as n FROM cloudtrail_events '
            'WHERE "errorCode" IS NOT NULL AND "errorCode" != \'\' '
            'GROUP BY "errorCode" ORDER BY n DESC LIMIT 20'
        )
        vals = ", ".join(repr(r) for r in df["errorCode"].tolist())
        sections.append(f"**errorCode** (top 20, non-null): {vals}")
        sections.append("")

        # ConsoleLogin errorMessage values (critical for hyp 1 & 2)
        df = run_query(
            'SELECT "eventName", "userIdentitytype", "errorMessage", count(*) as n '
            'FROM cloudtrail_events WHERE "eventName" = \'ConsoleLogin\' '
            'GROUP BY "eventName", "userIdentitytype", "errorMessage" ORDER BY n DESC'
        )
        rows = df.to_dict(orient="records")
        login_lines = [
            f"  eventName={r['eventName']!r}  userIdentitytype={r['userIdentitytype']!r}"
            f"  errorMessage={r['errorMessage']!r}  count={r['n']}"
            for r in rows
        ]
        sections.append("**ConsoleLogin breakdown** (exact values for hyp 1 & 2):")
        sections.extend(login_lines)
        sections.append("")

        return "\n".join(sections)

    except Exception as exc:
        logger.warning("Could not build data dictionary from DB: %s", exc)
        return "## Data Dictionary\n\n(unavailable — DB not connected)\n"


# ── System prompt (with data dictionary) ─────────────────────────────────────

_cached_system_prompt: str | None = None


def get_system_prompt(force_refresh: bool = False) -> str:
    """
    Return the system prompt with the data dictionary injected.
    Cached after the first call; pass force_refresh=True to rebuild.
    """
    global _cached_system_prompt
    if _cached_system_prompt is None or force_refresh:
        dd = build_data_dictionary()
        _cached_system_prompt = _SYSTEM_BASE.replace("{DATA_DICTIONARY}", dd)
        logger.info("System prompt built (%d chars).", len(_cached_system_prompt))
    return _cached_system_prompt


# ── User prompt template ──────────────────────────────────────────────────────

_USER_TEMPLATE_WITH_SCHEMA = """\
## Hypothesis
{hyp_text}

## Output schema
Your query MUST return exactly these columns (use these exact names in SELECT,
including any aliases): {output_columns}
{group_by_instruction}
Generate the SQL query and explanation JSON now.
"""

_USER_TEMPLATE_NO_SCHEMA = """\
## Hypothesis
{hyp_text}

Generate the SQL query and explanation JSON now.
"""


def build_repair_prompt(original_user_prompt: str, failed_sql: str, error: str) -> str:
    """
    Build a follow-up user prompt asking the LLM to fix a SQL query that failed
    EXPLAIN validation.  The original prompt context is preserved so the model
    retains full schema + output-schema awareness.
    """
    return (
        f"{original_user_prompt}\n\n"
        f"## Previous attempt FAILED\n\n"
        f"```sql\n{failed_sql}\n```\n\n"
        f"Execution error: `{error}`\n\n"
        f"Fix only the SQL error. Keep the same output columns and aggregation structure. "
        f"Generate the corrected query and explanation JSON now."
    )


def build_user_prompt(hypothesis: dict, expected_df=None) -> str:
    """
    Build the user-turn prompt for a single hypothesis.

    hypothesis: dict with at least 'hypothesis' key (the description text).
    expected_df: optional ground truth DataFrame — if provided, the expected
                 output columns and aggregation requirement are communicated
                 to the LLM.
    """
    import pandas as pd

    hyp_id   = str(hypothesis.get("id", ""))
    hyp_text = hypothesis.get("hypothesis", "")

    # Append any hypothesis-specific extra hints (e.g., regex extraction, GT size)
    extra_hint = HYP_EXTRA_HINTS.get(hyp_id, "")
    if extra_hint:
        hyp_text = hyp_text + "\n\n" + extra_hint

    if expected_df is None or (isinstance(expected_df, pd.DataFrame) and expected_df.empty):
        return _USER_TEMPLATE_NO_SCHEMA.format(hyp_text=hyp_text)

    cols = list(expected_df.columns)
    has_count = "count" in cols
    key_cols = [c for c in cols if c != "count"]

    col_list = ", ".join(f'"{c}"' for c in key_cols)
    if has_count:
        col_list += ', count(*) AS "count"'
        gb_cols = ", ".join(f'"{c}"' for c in key_cols)
        group_by_instruction = f'\nYour query MUST include GROUP BY {gb_cols}.'
    else:
        group_by_instruction = ""

    return _USER_TEMPLATE_WITH_SCHEMA.format(
        hyp_text=hyp_text,
        output_columns=col_list,
        group_by_instruction=group_by_instruction,
    )
